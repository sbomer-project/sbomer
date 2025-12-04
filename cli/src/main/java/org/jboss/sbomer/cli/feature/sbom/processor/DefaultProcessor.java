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
package org.jboss.sbomer.cli.feature.sbom.processor;

import static com.redhat.red.build.koji.model.json.KojiJsonConstants.TYPEINFO;
import static com.redhat.red.build.koji.model.json.KojiJsonConstants.URL;
import static org.jboss.sbomer.core.features.sbom.Constants.CONTAINER_PROPERTY_IMAGE_LABEL_COMPONENT;
import static org.jboss.sbomer.core.features.sbom.Constants.CONTAINER_PROPERTY_IMAGE_LABEL_RELEASE;
import static org.jboss.sbomer.core.features.sbom.Constants.CONTAINER_PROPERTY_IMAGE_LABEL_VERSION;
import static org.jboss.sbomer.core.features.sbom.Constants.SBOM_RED_HAT_BREW_BUILD_ID;
import static org.jboss.sbomer.core.features.sbom.Constants.SBOM_RED_HAT_ENVIRONMENT_IMAGE;
import static org.jboss.sbomer.core.features.sbom.Constants.SBOM_RED_HAT_PNC_BUILD_ID;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.addHashIfMissing;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.addMrrc;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.addPedigreeRemoteSource;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.getHash;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.hasExternalReference;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.setArtifactMetadata;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.setBrewBuildMetadata;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.setPncBuildMetadata;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.setPublisher;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.setSupplier;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.updatePurl;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Property;
import org.jboss.pnc.build.finder.koji.KojiBuild;
import org.jboss.pnc.dto.Artifact;
import org.jboss.sbomer.cli.feature.sbom.adjuster.PncBuildAdjuster;
import org.jboss.sbomer.cli.feature.sbom.client.CachitoClient;
import org.jboss.sbomer.cli.feature.sbom.client.CachitoResponse;
import org.jboss.sbomer.cli.feature.sbom.service.KojiService;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.enums.ProcessorType;
import org.jboss.sbomer.core.features.sbom.utils.RhVersionPattern;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.core.pnc.PncService;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.redhat.red.build.koji.KojiClientException;
import com.redhat.red.build.koji.model.xmlrpc.KojiBuildInfo;

import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DefaultProcessor implements Processor {
    private static final String REMOTE_SOURCES = "remote-sources";

    protected final PncService pncService;

    protected final KojiService kojiService;

    protected final CachitoClient cachitoClient;

    public DefaultProcessor(PncService pncService, KojiService kojiService, CachitoClient cachitoClient) {
        this.pncService = pncService;
        this.kojiService = kojiService;
        this.cachitoClient = cachitoClient;
    }

    private final Map<String, String> purlRelocations = new HashMap<>();

    /**
     * Performs processing for a given {@link Component}.
     *
     * @param component the component to process
     */
    protected void processComponent(Component component) {
        log.debug("Processing '{}'...", component.getPurl());

        if (component.getPurl() == null) {
            log.info("Component '{}' does not have a purl", component.getName());
            return;
        }

        if (component.getVersion() == null) {
            log.info("Component '{}' does not have a version", component.getName());
            return;
        }

        // If the component does not have "pnc-build-id" nor "pnc-environment-image" nor "brew-build-id", query it
        if (!hasExternalReference(component, ExternalReference.Type.BUILD_SYSTEM, SBOM_RED_HAT_PNC_BUILD_ID)
                && !hasExternalReference(component, ExternalReference.Type.BUILD_META, SBOM_RED_HAT_ENVIRONMENT_IMAGE)
                && !hasExternalReference(component, ExternalReference.Type.BUILD_SYSTEM, SBOM_RED_HAT_BREW_BUILD_ID)) {

            Optional<String> sha256 = getHash(component, Hash.Algorithm.SHA_256);
            Optional<String> sha1 = getHash(component, Hash.Algorithm.SHA1);
            Optional<String> md5 = getHash(component, Hash.Algorithm.MD5);

            // First, try to look up the artifact with the purl given and with optional SHA256 hash to filter out
            // results
            // Even though we may have different hashes, we specifically specify only SHA256 here.
            Artifact artifact = pncService.getArtifact(component.getPurl(), sha256, Optional.empty(), Optional.empty());

            // Artifact wasn't found, so we will try lookup using different methods
            if (artifact == null) {
                log.debug(
                        "Artifact with purl '{}' wasn't found in PNC, using different methods to receive it",
                        component.getPurl());

                if (hasAnyHash(sha256, sha1, md5)) {
                    log.debug(
                            "There is at least one hash available: sha256 '{}', sha1 '{}', md5 '{}'",
                            sha256.orElse(null),
                            sha1.orElse(null),
                            md5.orElse(null));

                    log.debug("Looking up '{}' artifact in PNC using hashes only", component.getPurl());

                    // Let's try a lookup with hashes only, because the generated purl can be wrongly constructed
                    artifact = pncService.getArtifact(null, sha256, sha1, md5);
                }

                // No luck, let's try to see if we can find hashes in build-meta external references
                if (artifact == null) {
                    log.debug(
                            "Artifact with purl '{}' wasn't found in PNC using hash-only lookup, giving up",
                            component.getPurl());
                    return;
                }

                String oldPurl = component.getPurl();
                String newPurl = artifact.getPurl();

                if (newPurl == null) {
                    log.warn(
                            "The PNC artifact '{}' does not have a purl set, we cannot update the purl in the component, leaving it as is: '{}'",
                            artifact.getId(),
                            oldPurl);
                } else {
                    // It looks like we found the artifact with a hash-only query, but the purl query failed on us.
                    // This means that the purl most probably is incorrect in the manifest, so let's update it.
                    log.debug("Updating component's purl from '{}' to '{}'", oldPurl, newPurl);

                    purlRelocations.put(oldPurl, newPurl);
                }
            }

            // Make sure the component has hashes
            addHashIfMissing(component, artifact.getMd5(), Hash.Algorithm.MD5);
            addHashIfMissing(component, artifact.getSha1(), Hash.Algorithm.SHA1);
            addHashIfMissing(component, artifact.getSha256(), Hash.Algorithm.SHA_256);

            log.info(
                    "Starting processing of Red Hat component '{}' with PNC artifact '{}'...",
                    component.getPurl(),
                    artifact.getId());

            // In case this is a RH artifact, add more properties.
            if (RhVersionPattern.isRhVersion(component.getVersion())
                    || RhVersionPattern.isRhPurl(component.getPurl())) {
                setPublisher(component);
                setSupplier(component);
                addMrrc(component);
            }

            // Add artifact metadata (PNC url)
            setArtifactMetadata(component, artifact, pncService.getApiUrl());

            // Add build-related information if we found a build in PNC
            if (artifact.getBuild() != null) {
                log.debug(
                        "Component '{}' was built in PNC, adding enrichment from PNC build '{}'",
                        component.getPurl(),
                        artifact.getBuild().getId());

                setPncBuildMetadata(component, artifact.getBuild(), pncService.getApiUrl());
            } else {
                if (RhVersionPattern.isRhVersion(component.getVersion())) {
                    // Lookup the build in Brew, as the artifact was found in PNC but without a build attached
                    log.debug(
                            "Component '{}' was not built in PNC, will search in Brew the corresponding artifact '{}'",
                            component.getPurl(),
                            artifact.getPublicUrl());
                    processBrewBuild(component, artifact);
                } else {
                    log.warn(
                            "Component '{}' was not built in PNC nor it is a RH artifact, this component won't be enriched, skipping",
                            component.getPurl());
                }
            }
        } else {
            log.debug(
                    "Component with purl '{}' is already enriched, skipping further processing for this component",
                    component.getPurl());
        }
    }

    // FIXME: 'Optional<String>' used as type for parameter 'sha256'
    private boolean hasAnyHash(Optional<String> sha256, Optional<String> sha1, Optional<String> md5) {
        return (sha256.orElse(null) != null || sha1.orElse(null) != null || md5.orElse(null) != null);
    }

    protected void processBrewBuild(Component component, Artifact artifact) {
        KojiBuild brewBuild = kojiService.findBuild(artifact);
        if (brewBuild != null) {

            log.debug(
                    "Component '{}' was built in Brew, adding enrichment from Brew build '{}'",
                    component.getPurl(),
                    brewBuild.getBuildInfo().getId());

            setBrewBuildMetadata(
                    component,
                    String.valueOf(brewBuild.getBuildInfo().getId()),
                    brewBuild.getSource(),
                    kojiService.getConfig().getKojiWebURL().toString());
        } else {
            log.debug("Component '{}' was not built in Brew, cannot add any enrichment!", component.getPurl());
        }
    }

    @Override
    public Bom process(Bom bom) {
        // TODO: this should be moved to its own workflow
        new PncBuildAdjuster().adjust(bom);

        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            Component component = bom.getMetadata().getComponent();

            // For container images, there is nothing to do for the metadata component.
            // All modifications are done in the main component.
            if (Objects.requireNonNull(component.getType()) != Component.Type.CONTAINER) {
                processComponent(component);
            }
        }

        if (bom.getComponents() != null) {
            for (Component c : bom.getComponents()) {

                if (Objects.requireNonNull(c.getType()) == Component.Type.CONTAINER) {
                    processContainerImageComponent(c);
                } else {
                    PackageURL purl = getPackageURL(c);
                    if (PackageURL.StandardTypes.RPM.equals(purl.getType())) {
                        processRpmComponent(c, purl);
                    } else {
                        processComponent(c);
                    }
                }
            }
        }

        // If there are any purl relocations, process these.
        purlRelocations.forEach((oldPurl, newPurl) -> updatePurl(bom, oldPurl, newPurl));

        if (SbomUtils.isNotEmpty(bom.getComponents())) {
            WorkaroundMissingNpmDependencies workaround = new WorkaroundMissingNpmDependencies(pncService);
            workaround.analyzeComponentsBuild(bom.getComponents().get(0));
            workaround.addMissingDependencies(bom);
        }

        return bom;
    }

    private void processRpmComponent(Component component, PackageURL purl) {
        Map<String, String> qualifiers = purl.getQualifiers();
        String arch = null;

        if (qualifiers != null) {
            arch = qualifiers.get("arch");
        }

        if (arch == null) {
            log.debug("RPM purl is missing arch qualifier: '{}'", component.getPurl());
            return;
        }

        KojiBuildInfo buildInfo;
        try {
            String nvra = purl.getName() + "-" + purl.getVersion() + "." + arch;
            buildInfo = kojiService.findBuildByRPM(nvra);
        } catch (KojiClientException e) {
            log.error("Lookup in Brew failed due to {}", e.getMessage() == null ? e.toString() : e.getMessage(), e);
            return;
        }

        if (buildInfo == null) {
            log.warn("No Brew build information was retrieved, will not add any information to RPM component");
            return;
        }

        // It is a RH image, set publisher and supplier
        setPublisher(component);
        setSupplier(component);

        // Add additional metadata
        setBrewBuildMetadata(
                component,
                String.valueOf(buildInfo.getId()),
                Optional.ofNullable(buildInfo.getSource()),
                kojiService.getConfig().getKojiWebURL().toString());
    }

    private void processContainerImageComponent(Component component) {
        // Try to find required properties
        Optional<Property> componentOpt = SbomUtils
                .findPropertyWithNameInComponent(CONTAINER_PROPERTY_IMAGE_LABEL_COMPONENT, component);
        Optional<Property> versionOpt = SbomUtils
                .findPropertyWithNameInComponent(CONTAINER_PROPERTY_IMAGE_LABEL_VERSION, component);
        Optional<Property> releaseOpt = SbomUtils
                .findPropertyWithNameInComponent(CONTAINER_PROPERTY_IMAGE_LABEL_RELEASE, component);

        if (componentOpt.isEmpty() || versionOpt.isEmpty() || releaseOpt.isEmpty()) {
            log.warn(
                    "One or more required properties was not found in the component, skipping adding RH-specific metadata for this container image");
            return;
        }

        String nvr = String
                .join("-", componentOpt.get().getValue(), versionOpt.get().getValue(), releaseOpt.get().getValue());

        log.debug("Looking up container information in Brew for NVR '{}'", nvr);

        KojiBuildInfo buildInfo;

        try {
            buildInfo = kojiService.findBuild(nvr);
        } catch (KojiClientException e) {
            log.error("Lookup in Brew failed due to {}", e.getMessage() == null ? e.toString() : e.getMessage(), e);
            return;
        }

        if (buildInfo == null) {
            log.warn("No Brew build information was retrieved, will not add any information to image component");
            return;
        }

        // It is a RH image, set publisher and supplier
        setPublisher(component);
        setSupplier(component);

        addPedigreeFromBuildInfo(cachitoClient, component, buildInfo);

        // Add additional metadata
        setBrewBuildMetadata(
                component,
                String.valueOf(buildInfo.getId()),
                Optional.ofNullable(buildInfo.getSource()),
                kojiService.getConfig().getKojiWebURL().toString());
    }

    private static List<Map<String, Object>> getRemoteSources(KojiBuildInfo buildInfo) {
        Map<String, Object> extra = buildInfo.getExtra();

        if (extra == null || extra.isEmpty()) {
            return Collections.emptyList();
        }

        Map<String, Object> typeinfo = (Map<String, Object>) extra.getOrDefault(TYPEINFO, Collections.emptyMap());
        List<Map<String, Object>> remoteSources = (List<Map<String, Object>>) typeinfo
                .getOrDefault(REMOTE_SOURCES, Collections.emptyList());

        if (remoteSources.isEmpty()) {
            return Collections.emptyList();
        }

        return Collections.unmodifiableList(remoteSources);
    }

    public static Optional<URI> getUriFromBuildInfo(KojiBuildInfo buildInfo) {
        List<Map<String, Object>> remoteSources = getRemoteSources(buildInfo);

        if (remoteSources.isEmpty()) {
            return Optional.empty();
        }

        Map<String, Object> remoteSource = remoteSources.get(0);
        String url = remoteSource.getOrDefault(URL, "").toString();

        if (url.isEmpty()) {
            return Optional.empty();
        }

        try {
            URI uri = new URI(url);
            URI newUri = new URI(uri.getScheme(), uri.getHost(), null, null);
            return Optional.ofNullable(newUri);
        } catch (URISyntaxException e) {
            return Optional.empty();
        }
    }

    @SuppressWarnings("unchecked")
    public static List<String> getCachitoRequestIdsFromBuildInfo(KojiBuildInfo buildInfo) {
        List<Map<String, Object>> remoteSources = getRemoteSources(buildInfo);

        if (remoteSources.isEmpty()) {
            return Collections.emptyList();
        }

        List<String> ids = new ArrayList<>(remoteSources.size());

        for (Map<String, Object> remoteSource : remoteSources) {
            String url = (String) remoteSource.getOrDefault(URL, null);

            if (url == null) {
                continue;
            }

            URI uri = URI.create(url).normalize();
            String id = uri.getPath().replaceAll("/api/v1/requests/(\\d+)", "$1");
            ids.add(id);
        }

        return Collections.unmodifiableList(ids);
    }

    public static void addPedigreeFromBuildInfo(
            CachitoClient cachitoClient,
            Component component,
            KojiBuildInfo buildInfo) {
        Optional<URI> buildUri = getUriFromBuildInfo(buildInfo);
        List<String> ids = getCachitoRequestIdsFromBuildInfo(buildInfo);

        for (String id : ids) {
            Response response = cachitoClient.getRequestById(id);
            int status = response.getStatus();

            if (status != Response.Status.OK.getStatusCode()) {
                log.warn("Unable to retrieve Cachito request with ID '{}', status: {}", id, status);
                continue;
            }

            CachitoResponse cachitoResponse = response.readEntity(CachitoResponse.class);
            String repo = cachitoResponse.getRepo();
            String ref = cachitoResponse.getRef();
            log.debug("Adding pedigree from Cachito request with ID '{}', repo: '{}', ref: '{}'", id, repo, ref);
            addPedigreeRemoteSource(component, repo, ref);
        }
    }

    @Override
    public ProcessorType getType() {
        return ProcessorType.DEFAULT;
    }

    public static PackageURL getPackageURL(Component component) {
        try {
            return new PackageURL(component.getPurl());
        } catch (MalformedPackageURLException e) {
            throw new ApplicationException("Unable to parse provided purl: '{}'", component.getPurl(), e);
        }
    }

}
