/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.sbomer.cli.feature.sbom.service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

import org.apache.commons.collections4.MultiValuedMap;
import org.eclipse.microprofile.context.ManagedExecutor;
import org.eclipse.microprofile.faulttolerance.Retry;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.pnc.build.finder.core.BuildConfig;
import org.jboss.pnc.build.finder.core.BuildFinder;
import org.jboss.pnc.build.finder.core.BuildFinderListener;
import org.jboss.pnc.build.finder.core.BuildSystem;
import org.jboss.pnc.build.finder.core.BuildSystemInteger;
import org.jboss.pnc.build.finder.core.ChecksumType;
import org.jboss.pnc.build.finder.core.DistributionAnalyzer;
import org.jboss.pnc.build.finder.core.DistributionAnalyzerListener;
import org.jboss.pnc.build.finder.core.LocalFile;
import org.jboss.pnc.build.finder.koji.ClientSession;
import org.jboss.pnc.build.finder.koji.KojiBuild;
import org.jboss.pnc.dto.Artifact;
import org.jboss.sbomer.cli.feature.sbom.client.KojiDownloadClient;
import org.jboss.sbomer.cli.feature.sbom.utils.buildfinder.FinderStatus;
import org.jboss.sbomer.core.errors.ApplicationException;

import com.redhat.red.build.koji.KojiClientException;
import com.redhat.red.build.koji.model.json.BuildExtraInfo;
import com.redhat.red.build.koji.model.json.RemoteSourcesExtraInfo;
import com.redhat.red.build.koji.model.json.TypeInfoExtraInfo;
import com.redhat.red.build.koji.model.json.util.KojiObjectMapper;
import com.redhat.red.build.koji.model.xmlrpc.KojiBuildInfo;
import com.redhat.red.build.koji.model.xmlrpc.KojiIdOrName;
import com.redhat.red.build.koji.model.xmlrpc.KojiRpmInfo;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import static org.jboss.sbomer.core.rest.faulttolerance.Constants.KOJI_SERVICE_DELAY;
import static org.jboss.sbomer.core.rest.faulttolerance.Constants.KOJI_SERVICE_MAX_RETRIES;

/**
 * A service to interact with the Koji (Brew) build system.
 */
@Slf4j
@ApplicationScoped
public class KojiService {

    private static final int MAX_BREW_WAIT_MIN = 5;
    private static final KojiObjectMapper MAPPER = new KojiObjectMapper();
    public static final String REMOTE_SOURCE_PREFIX = "remote-source";
    public static final String REMOTE_SOURCE_DELIMITER = "-";
    public static final String SOURCES_FILE_ARCHIVE_SUFFIX = ".tar.gz";
    public static final String SOURCES_FILE_METADATA_SUFFIX = ".json";

    @Inject
    ManagedExecutor executor;

    @Getter
    @Inject
    BuildConfig config;

    @Inject
    @Setter
    ClientSession kojiSession;

    @Inject
    @RestClient
    @Setter
    KojiDownloadClient kojiDownloadClient;

    /**
     * Executes analysis of the provided archives identified by URLs, which must be downloadable using HTTP(S). The
     * operation is executed synchronously, but the analysis itself runs several executors in parallel.
     *
     * @param url The URL to retrieve
     * @param distributionAnalyzerListener A listener for events from DistributionAnalyzer
     * @param buildFinderListener A listener for events from Buildfinder
     *
     * @return Results of the analysis if the whole operation was successful.
     * @throws Throwable Thrown in case of any errors during the analysis
     */
    private List<KojiBuild> find(
            String url,
            DistributionAnalyzerListener distributionAnalyzerListener,
            BuildFinderListener buildFinderListener) throws Throwable {

        Future<List<KojiBuild>> finderTask = executor.submit(() -> {
            try {
                return find(URI.create(url).normalize().toURL(), distributionAnalyzerListener, buildFinderListener);
            } catch (KojiClientException | MalformedURLException e) {
                throw new ExecutionException(e);
            }
        });

        return awaitResults(finderTask);
    }

    /**
     * @param url url to analyze
     * @param distributionAnalyzerListener A listener for events from DistributionAnalyzer
     * @param buildFinderListener A listener for events from Build Finder
     *
     * @return the list of only the builds built in Brew
     * @throws KojiClientException Thrown in case of exceptions with Koji communication
     */
    private List<KojiBuild> find(
            URL url,
            DistributionAnalyzerListener distributionAnalyzerListener,
            BuildFinderListener buildFinderListener) throws KojiClientException {

        List<String> files = Collections.singletonList(url.toExternalForm());

        log.info("Starting analysis for '{}' with config {}", url.toExternalForm(), config);

        DistributionAnalyzer analyzer = new DistributionAnalyzer(files, config, null);
        analyzer.setListener(distributionAnalyzerListener);

        Map<ChecksumType, MultiValuedMap<String, LocalFile>> checksums;
        try {
            checksums = analyzer.call();
        } catch (IOException e) {
            throw new RuntimeException("Failed to analyze checksums", e);
        }

        BuildFinder buildFinder = new BuildFinder(kojiSession, config, analyzer);
        buildFinder.setListener(buildFinderListener);

        Map<BuildSystemInteger, KojiBuild> builds = buildFinder.call();
        int size = builds.size();
        int numBuilds = size >= 1 ? size - 1 : 0;

        log.debug("Got {} checksum types and {} builds", checksums.size(), numBuilds);

        List<KojiBuild> brewBuilds = builds.entrySet()
                .stream()
                .filter(entry -> entry.getKey().getBuildSystem().equals(BuildSystem.koji))
                .map(Map.Entry::getValue)
                .toList();

        log.info("Finished analysis for '{}'", url.toExternalForm());

        return brewBuilds;
    }

    private List<KojiBuild> awaitResults(Future<List<KojiBuild>> finderTask) throws Throwable {
        try {
            return finderTask.get(MAX_BREW_WAIT_MIN, TimeUnit.MINUTES);
        } catch (TimeoutException e) {
            log.debug("Timeout waiting for build results");
            return Collections.emptyList();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Collections.emptyList();
        } catch (ExecutionException e) { // NOSONAR We are rethrowing it.
            log.debug("Analysis failed due to {}", e.getMessage(), e);
            throw e.getCause();
        }
    }

    @Retry(maxRetries = KOJI_SERVICE_MAX_RETRIES, delay = KOJI_SERVICE_DELAY, delayUnit = ChronoUnit.SECONDS)
    public KojiBuild findBuild(Artifact artifact) throws Throwable {
        if (artifact.getPublicUrl() == null) {
            return null;
        }

        FinderStatus status = new FinderStatus();
        log.trace("Searching for artifact '{}' in Brew...", artifact.getPublicUrl());
        List<KojiBuild> brewBuilds = find(artifact.getPublicUrl(), status, status);
        if (brewBuilds.size() == 1) {
            log.trace(
                    "Found Brew build with id {} of artifact: '{}'",
                    brewBuilds.get(0).getId(),
                    artifact.getPublicUrl());
            return brewBuilds.get(0);
        } else if (brewBuilds.size() > 1) {
            String brewBuildIds = brewBuilds.stream().map(KojiBuild::getId).collect(Collectors.joining(", "));
            log.warn(
                    "Multiple builds (with ids: {}) where found in Brew of the artifact '{}', picking the first one!",
                    brewBuildIds,
                    artifact.getPublicUrl());
            return brewBuilds.get(0);
        }
        return null;
    }

    @Retry(maxRetries = KOJI_SERVICE_MAX_RETRIES, delay = KOJI_SERVICE_DELAY, delayUnit = ChronoUnit.SECONDS)
    public KojiBuildInfo findBuildByRPM(String nvra) throws KojiClientException {
        if (nvra == null) {
            return null;
        }

        log.debug("Finding Brew build for RPM '{}'...", nvra);

        List<KojiRpmInfo> rpm = kojiSession.getRPM(List.of(new KojiIdOrName(nvra)));

        if (rpm.isEmpty()) {
            log.debug("RPM list for {} is empty", nvra);
            return null;
        }
        KojiRpmInfo rpmInfo = rpm.get(0);

        // It could happen that the returned RPM info is null.
        if (rpmInfo == null) {
            log.debug("RPM info for {} is null", nvra);
            return null;
        }

        if (rpm.size() > 1) {
            log.warn(
                    "Multiple RPMs {} found in Brew, this should not happen. Did Kojiji have a breaking change"
                            + " update? Selected the first one {}",
                    nvra,
                    rpmInfo.getId());
        }

        if (rpmInfo.getBuildId() == null) {
            log.debug("RPM {} does not have assigned build", rpmInfo.getId());
            return null;
        }

        KojiBuildInfo buildInfo = kojiSession.getBuild(rpmInfo.getBuildId());

        log.debug("Found build: '{}'...", buildInfo.getId());
        return buildInfo;
    }

    @Retry(maxRetries = KOJI_SERVICE_MAX_RETRIES, delay = KOJI_SERVICE_DELAY, delayUnit = ChronoUnit.SECONDS)
    public KojiBuildInfo findBuild(int id) throws KojiClientException {
        log.debug("Retrieving Brew build with id '{}'...", id);

        KojiBuildInfo build = kojiSession.getBuild(id);

        if (build == null) {
            log.warn("Build with id {} not found", id);
            return null;
        }

        return build;
    }

    @Retry(maxRetries = KOJI_SERVICE_MAX_RETRIES, delay = KOJI_SERVICE_DELAY, delayUnit = ChronoUnit.SECONDS)
    public KojiBuildInfo findBuild(String nvr) throws KojiClientException {
        if (nvr == null) {
            return null;
        }

        log.debug("Finding Brew build for NVR '{}'...", nvr);

        List<KojiBuildInfo> builds = kojiSession.getBuild(List.of(KojiIdOrName.getFor(nvr)));

        if (builds.isEmpty()) {
            log.debug("Builds list for {} is empty", nvr);
            return null;
        }

        if (builds.size() == 1) {
            KojiBuildInfo buildInfo = builds.get(0);

            // It could happen that the returned build info is null.
            if (buildInfo == null) {
                log.debug("Build info for {} is null", nvr);
                return null;
            }

            log.debug("Found a single build: '{}'...", buildInfo.getId());
            return buildInfo;
        }

        log.warn("Found more than one build for NVR '{}', this is unexpected, returning nothing!", nvr);
        log.debug("{}", builds);

        return null;
    }

    public void downloadSourcesFiles(KojiBuildInfo buildInfo, Path outputDir) {
        try {
            Files.createDirectories(outputDir);
            String remoteSourcesName = retrieveRemoteSourcesName(buildInfo);
            if (remoteSourcesName == null) {
                log.warn("Unable to download sources archive and metadata files due to no remote sources name");
                return;
            }
            downloadSourcesFile(remoteSourcesName + SOURCES_FILE_ARCHIVE_SUFFIX, buildInfo, outputDir);
            downloadSourcesFile(remoteSourcesName + SOURCES_FILE_METADATA_SUFFIX, buildInfo, outputDir);
        } catch (ApplicationException e) {
            throw e;
        } catch (Exception e) {
            throw new ApplicationException("Failed to download sources archive or metadata file", e);
        }
    }

    private void downloadSourcesFile(String sourcesFileName, KojiBuildInfo buildInfo, Path outputDir)
            throws IOException {
        Path sourcesFile = outputDir.resolve(sourcesFileName);
        log.info("Downloading sources file '{}'", sourcesFile.toAbsolutePath());
        try (Response response = kojiDownloadClient.downloadSourcesFile(
                buildInfo.getName(),
                buildInfo.getVersion(),
                buildInfo.getRelease(),
                sourcesFileName)) {
            if (response.getStatus() != Response.Status.OK.getStatusCode()) {
                throw new ApplicationException("Failed to download sources file: HTTP " + response.getStatus());
            }
            try (InputStream in = response.readEntity(InputStream.class);
                    OutputStream out = Files.newOutputStream(
                            sourcesFile,
                            StandardOpenOption.CREATE,
                            StandardOpenOption.TRUNCATE_EXISTING)) {
                in.transferTo(out);
            }
            log.info("Successfully downloaded sources file");
        }
    }

    private String retrieveRemoteSourcesName(KojiBuildInfo buildInfo) {
        BuildExtraInfo buildExtraInfo = MAPPER.convertValue(buildInfo.getExtra(), BuildExtraInfo.class);
        // Sometimes remote sources might not exist
        List<RemoteSourcesExtraInfo> remoteSourcesExtraInfos = Optional.ofNullable(buildExtraInfo)
                .map(BuildExtraInfo::getTypeInfo)
                .map(TypeInfoExtraInfo::getRemoteSourcesExtraInfo)
                .orElse(Collections.emptyList());
        if (remoteSourcesExtraInfos.isEmpty()) {
            log.warn("Unable to retrieve remote sources name");
            return null;
        }
        String name = remoteSourcesExtraInfos.get(0).getName();
        // Sometimes remote sources might have no name
        if (name == null) {
            return REMOTE_SOURCE_PREFIX;
        } else {
            return REMOTE_SOURCE_PREFIX + REMOTE_SOURCE_DELIMITER + name;
        }
    }

}
