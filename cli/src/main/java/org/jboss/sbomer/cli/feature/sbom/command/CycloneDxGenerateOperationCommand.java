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
package org.jboss.sbomer.cli.feature.sbom.command;

import static org.jboss.sbomer.core.features.sbom.Constants.SBOM_RED_HAT_DELIVERABLE_CHECKSUM;
import static org.jboss.sbomer.core.features.sbom.Constants.SBOM_RED_HAT_DELIVERABLE_URL;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.addPropertyIfMissing;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.createBom;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.createComponent;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.createDefaultSbomerMetadata;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.createDependency;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.getHashesFromAnalyzedDistribution;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.setArtifactMetadata;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.setPncBuildMetadata;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.setPncOperationMetadata;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.setProductMetadata;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.toJsonNode;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Component.Scope;
import org.cyclonedx.model.Component.Type;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Hash;
import org.jboss.pnc.dto.DeliverableAnalyzerOperation;
import org.jboss.pnc.dto.ProductMilestone;
import org.jboss.pnc.dto.ProductVersion;
import org.jboss.pnc.dto.response.AnalyzedArtifact;
import org.jboss.sbomer.cli.feature.sbom.adjuster.PncOperationAdjuster;
import org.jboss.sbomer.cli.feature.sbom.processor.WorkaroundMissingNpmDependencies;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.config.OperationConfig;
import org.jboss.sbomer.core.features.sbom.enums.GeneratorType;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import com.redhat.red.build.koji.KojiClientException;
import com.redhat.red.build.koji.model.xmlrpc.KojiBuildInfo;

import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine.Command;

@Slf4j
@Command(
        mixinStandardHelpOptions = true,
        name = "cyclonedx-operation",
        description = "SBOM generation for deliverable analyzer operations by manually creating a CycloneDX compliant SBOM")
public class CycloneDxGenerateOperationCommand extends AbstractGenerateOperationCommand {

    public static final String SBOM_REPRESENTING_THE_DELIVERABLE = "SBOM representing the deliverable ";

    @Override
    protected GeneratorType generatorType() {
        return GeneratorType.CYCLONEDX_OPERATION;
    }

    @Override
    protected Path doGenerate() {

        OperationConfig config;

        try {
            config = ObjectMapperProvider.json()
                    .readValue(getParent().getConfigPath().toAbsolutePath().toFile(), OperationConfig.class);
        } catch (StreamReadException e) {
            log.error("Unable to parse the configuration file", e);
            throw new ApplicationException("Unable to parse the operation configuration file");
        } catch (DatabindException e) {
            log.error("Unable to deserialize the configuration file", e);
            throw new ApplicationException("Unable to deserialize the configuration file");
        } catch (IOException e) {
            log.error("Unable to read configuration file", e);
            throw new ApplicationException("Unable to read configuration file");
        }

        // Create the empty SBOM
        Bom bom = createBom();
        if (bom == null) {
            throw new ApplicationException("Unable to create a new Bom");
        }

        String deliverableUrl;
        try {
            String url = config.getDeliverableUrls().get(getParent().getIndex());
            deliverableUrl = URI.create(url).normalize().toURL().toString();
        } catch (MalformedURLException e) {
            String url = config.getDeliverableUrls().get(getParent().getIndex());
            throw new ApplicationException("Could not parse deliverable URL " + url, e);
        }

        log.info(
                "Generating CycloneDX compliant SBOM for the deliverable: {}, with index: {}, with the provided config: {}",
                deliverableUrl,
                getParent().getIndex(),
                config);

        // Get some metadata about the operation
        String productName;
        String productMilestone = "";
        DeliverableAnalyzerOperation operation = pncService.getDeliverableAnalyzerOperation(config.getOperationId());
        if (operation.getProductMilestone() != null) {
            ProductMilestone milestone = pncService.getMilestone(operation.getProductMilestone().getId());
            if (milestone != null && milestone.getProductVersion() != null) {
                ProductVersion productVersion = pncService.getProductVersion(milestone.getProductVersion().getId());
                productName = productVersion.getProduct().getName().replace(" ", "-").toLowerCase();
                productMilestone = milestone.getVersion();

                log.info("Retrieved Product: {}, Milestone: {}", productName, productMilestone);
            }
        }

        // Get all the analyzed artifacts retrieved in the deliverable analyzer operation
        List<AnalyzedArtifact> allAnalyzedArtifacts = pncService.getAllAnalyzedArtifacts(config.getOperationId());

        // A single operation might include multiple archives, filter only the ones related to this particular
        // distribution. If no distribution is present, keep them all because it's an old analysis with older and fewer
        // metadata.
        boolean isLegacyAnalysis = allAnalyzedArtifacts.stream().anyMatch(a -> a.getDistribution() == null);
        List<AnalyzedArtifact> artifactsToManifest = isLegacyAnalysis ? allAnalyzedArtifacts
                : allAnalyzedArtifacts.stream()
                        .filter(a -> deliverableUrl.equals(a.getDistribution().getDistributionUrl()))
                        .toList();

        Optional<List<Hash>> distributionHashes;
        Optional<String> distributionSha256;

        if (isLegacyAnalysis) {
            log.info(
                    "The deliverable analysis operation '{}' seems to be old because it does not have the distribution metadata and all the filename match info; filtering cannot be done so the final manifest will contain ALL the content of ALL the deliverable urls (if multiple). Total analyzed artifacts in the operation: '{}'",
                    config.getOperationId(),
                    allAnalyzedArtifacts.size());
            // If its legacy analysis do not attempt to set distro hashes
            distributionHashes = Optional.empty();
            distributionSha256 = Optional.empty();
        } else {
            log.info(
                    "Retrieved {} artifacts in the specified deliverable: '{}', out of {} total analyzed artifacts in the operation: '{}'",
                    artifactsToManifest.size(),
                    deliverableUrl,
                    allAnalyzedArtifacts.size(),
                    config.getOperationId());

            // Return optional list of hashes from the first artifact (distro)
            distributionHashes = !artifactsToManifest.isEmpty()
                    ? Optional.of(getHashesFromAnalyzedDistribution(artifactsToManifest.get(0).getDistribution()))
                    : Optional.empty();

            distributionSha256 = distributionHashes.stream()
                    .flatMap(List::stream)
                    .filter(hash -> Hash.Algorithm.SHA_256.getSpec().equals(hash.getAlgorithm()))
                    .map(Hash::getValue)
                    .findFirst();
        }

        String fileName = extractFilenameFromURL(deliverableUrl);

        // Create the main component PURL and version, plus description
        String desc = SBOM_REPRESENTING_THE_DELIVERABLE + fileName + " with ";
        String distributionPurl = createGenericPurl(fileName, distributionSha256);
        String distributionVersion = productMilestone;
        if (distributionSha256.isPresent()) {
            distributionVersion = "sha256:" + distributionSha256.get();
            desc += "checksum " + distributionVersion;
        } else {
            desc += "version " + distributionVersion;
        }

        Component mainComponent = createComponent(
                null,
                fileName,
                distributionVersion,
                desc,
                distributionPurl,
                Type.FILE);

        // If there are no hashes then dont attempt to set them
        if (!distributionHashes.isEmpty() && !distributionHashes.get().isEmpty()) {
            mainComponent.setHashes(distributionHashes.get());
        }

        Dependency mainDependency = createDependency(distributionPurl);

        setProductMetadata(mainComponent, config);
        setPncOperationMetadata(mainComponent, operation, pncService.getApiUrl());
        addPropertyIfMissing(mainComponent, SBOM_RED_HAT_DELIVERABLE_URL, deliverableUrl);
        addPropertyIfMissing(mainComponent, SBOM_RED_HAT_DELIVERABLE_CHECKSUM, distributionVersion);

        bom.setMetadata(createDefaultSbomerMetadata(mainComponent, sbomerClientFacade.getSbomerVersion()));
        bom.addDependency(mainDependency);

        Map<String, Component> purlToComponents = new HashMap<>();
        Map<String, Dependency> purl256ToDependencies = new HashMap<>();
        Map<String, Dependency> pathToDependencies = new TreeMap<>();

        purlToComponents.put(distributionPurl, mainComponent);
        purl256ToDependencies.put(distributionPurl, mainDependency);
        WorkaroundMissingNpmDependencies workaround = new WorkaroundMissingNpmDependencies(pncService);

        for (AnalyzedArtifact artifact : artifactsToManifest) {
            if (SbomUtils.isDistributionArtifact(artifact.getArtifact(), fileName, distributionHashes)
                    && SbomUtils.hasUnusablePurl(artifact.getArtifact())) {
                log.info(
                        "Skipping artifact '{}' — matches the distribution component by filename and checksum",
                        artifact.getArtifact().getFilename());
                continue;
            }

            String artifactPurl = artifact.getArtifact().getPurl();

            if (SbomUtils.hasUnusablePurl(artifact.getArtifact())) {
                String rebuilt = createGenericPurl(
                        artifact.getArtifact().getFilename(),
                        Optional.ofNullable(artifact.getArtifact().getSha256()));
                log.info(
                        "Artifact '{}' has no target repository and an unusable purl, rebuilding from '{}' to '{}'",
                        artifact.getArtifact().getFilename(),
                        artifactPurl,
                        rebuilt);
                artifactPurl = rebuilt;
            }

            // Create the component if not already created (e.g., the same pom can be a plain .pom or embedded as
            // pom.xml)
            if (!purlToComponents.containsKey(artifactPurl)) {
                // Create a component entry for the artifact
                Component component = createComponent(artifact, Scope.REQUIRED, Type.LIBRARY);

                // Override the purl/bomRef if we rebuilt it
                if (!artifactPurl.equals(artifact.getArtifact().getPurl())) {
                    component.setPurl(artifactPurl);
                    component.setBomRef(artifactPurl);
                }

                setArtifactMetadata(component, artifact.getArtifact(), pncService.getApiUrl());
                setPncBuildMetadata(component, artifact.getArtifact().getBuild(), pncService.getApiUrl());

                if (artifact.getArtifact().getBuild() != null) {
                    // Artifact was built in PNC, so it has all the data we need
                    workaround.analyzeBuild(component, artifact.getArtifact().getBuild());
                } else if (artifact.getBrewId() != null && artifact.getBrewId() > 0) {
                    setBrewBuildMetadata(component, artifact);
                } else {
                    log.warn(
                            "An artifact has been found with no associated build: '{}'. It will be added in the SBOM with generic type.",
                            artifact.getArtifact().getFilename());
                }

                // Add the component to the SBOM and to the internal cache
                bom.addComponent(component);
                purlToComponents.put(artifactPurl, component);

                // Create a dependency entry
                Dependency dependency = createDependency(artifactPurl);

                // Add the dependency to the BOM and to the internal caches
                bom.addDependency(dependency);
                purl256ToDependencies.put(artifactPurl, dependency);
            }

            // Add the filepath -> dependency data to the cache, which is used to compute the dependency hierarchy.
            // The same dependency (identified by purl) might be present in multiple locations inside the zip, with
            // different filepath
            Dependency dep = purl256ToDependencies.get(artifactPurl);
            Optional.ofNullable(artifact.getArchiveFilenames())
                    .orElse(List.of())
                    .forEach(filename -> pathToDependencies.put(filename, dep));
        }

        // Find the parent to set the correct hierarchy, default to the main root dependency
        for (Map.Entry<String, Dependency> entry : pathToDependencies.entrySet()) {
            String key = entry.getKey();
            Dependency dependency = entry.getValue();
            Optional<Dependency> maybeParent = findClosestParent(pathToDependencies, key);
            Dependency parent = maybeParent.orElse(mainDependency);
            parent.addDependency(dependency);
        }

        workaround.addMissingDependencies(bom);

        // Adjust the bom if needed (e.g., add the serial number)
        new PncOperationAdjuster().adjust(bom);

        Path sbomDirPath = Path.of(
                parent.getWorkdir().toAbsolutePath().toString(),
                String.valueOf(getParent().getIndex()),
                "bom.json");

        try {
            // Create all non-existent parent directories
            Files.createDirectories(sbomDirPath.getParent());

            ObjectMapperProvider.json()
                    .writerWithDefaultPrettyPrinter()
                    .writeValue(sbomDirPath.toFile(), toJsonNode(bom));

        } catch (JsonProcessingException e) {
            log.error(e.getMessage(), e);
            throw new ApplicationException("Unable to parse SBOM generated in " + sbomDirPath.toAbsolutePath());
        } catch (IOException e) {
            log.error(e.getMessage(), e);
            throw new ApplicationException("Unable to write the SBOM generated to " + sbomDirPath.toAbsolutePath());
        }

        return sbomDirPath;
    }

    private void setBrewBuildMetadata(Component component, AnalyzedArtifact artifact) {
        KojiBuildInfo brewBuild;
        try {
            brewBuild = kojiService.findBuild(artifact.getBrewId().intValue());
            if (brewBuild != null) {
                SbomUtils.setBrewBuildMetadata(
                        component,
                        String.valueOf(brewBuild.getId()),
                        Optional.ofNullable(brewBuild.getSource()),
                        kojiService.getConfig().getKojiWebURL().toString());
            }
        } catch (KojiClientException e) {
            log.error("Failed to retrieve brew build.", e);
        }
    }

    private String extractFilenameFromURL(String url) {
        try {
            return Paths.get(new URI(url).getPath()).getFileName().toString();
        } catch (Exception e) {
            return null;
        }
    }

    // FIXME: 'Optional<String>' used as type for parameter 'sha256'
    private String createGenericPurl(String filename, Optional<String> sha256) {
        try {
            PackageURLBuilder purlBuilder = PackageURLBuilder.aPackageURL()
                    .withType(PackageURL.StandardTypes.GENERIC)
                    .withName(filename);
            sha256.ifPresent(s -> purlBuilder.withQualifier("checksum", "sha256:" + s));

            return purlBuilder.build().toString();
        } catch (MalformedPackageURLException e) {
            return "pkg:generic/" + filename;
        }
    }

    private Optional<Dependency> findClosestParent(Map<String, Dependency> pathToDependencies, String path) {
        while (!path.isEmpty()) {
            // Find the parent if it exists
            int lastIndex = path.lastIndexOf("!/");
            if (lastIndex != -1) {
                path = path.substring(0, lastIndex);
            } else {
                break; // No more parent
            }
            if (pathToDependencies.get(path) != null) {
                return Optional.of(pathToDependencies.get(path));
            }
        }
        return Optional.empty();
    }
}
