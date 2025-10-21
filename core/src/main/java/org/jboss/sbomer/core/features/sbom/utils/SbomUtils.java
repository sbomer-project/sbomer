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
package org.jboss.sbomer.core.features.sbom.utils;

import static java.nio.charset.StandardCharsets.UTF_8;

import static org.jboss.sbomer.core.features.sbom.Constants.CONTAINER_PROPERTY_SYFT_PREFIX;
import static org.jboss.sbomer.core.features.sbom.Constants.MRRC_URL;
import static org.jboss.sbomer.core.features.sbom.Constants.PACKAGE_LANGUAGE;
import static org.jboss.sbomer.core.features.sbom.Constants.PROPERTY_ERRATA_PRODUCT_NAME;
import static org.jboss.sbomer.core.features.sbom.Constants.PROPERTY_ERRATA_PRODUCT_VARIANT;
import static org.jboss.sbomer.core.features.sbom.Constants.PROPERTY_ERRATA_PRODUCT_VERSION;
import static org.jboss.sbomer.core.features.sbom.Constants.PUBLISHER;
import static org.jboss.sbomer.core.features.sbom.Constants.SBOMER_GIT_URL;
import static org.jboss.sbomer.core.features.sbom.Constants.SBOMER_LICENSE_ID;
import static org.jboss.sbomer.core.features.sbom.Constants.SBOMER_LICENSE_URL;
import static org.jboss.sbomer.core.features.sbom.Constants.SBOMER_NAME;
import static org.jboss.sbomer.core.features.sbom.Constants.SBOMER_WEBSITE;
import static org.jboss.sbomer.core.features.sbom.Constants.SBOM_RED_HAT_BREW_BUILD_ID;
import static org.jboss.sbomer.core.features.sbom.Constants.SBOM_RED_HAT_ENVIRONMENT_IMAGE;
import static org.jboss.sbomer.core.features.sbom.Constants.SBOM_RED_HAT_PNC_ARTIFACT_ID;
import static org.jboss.sbomer.core.features.sbom.Constants.SBOM_RED_HAT_PNC_BUILD_ID;
import static org.jboss.sbomer.core.features.sbom.Constants.SBOM_RED_HAT_PNC_OPERATION_ID;
import static org.jboss.sbomer.core.features.sbom.Constants.SUPPLIER_NAME;
import static org.jboss.sbomer.core.features.sbom.Constants.SUPPLIER_URL;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.commonjava.atlas.maven.ident.ref.SimpleArtifactRef;
import org.commonjava.atlas.npm.ident.ref.NpmPackageRef;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Commit;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Component.Scope;
import org.cyclonedx.model.Component.Type;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Hash.Algorithm;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.OrganizationalEntity;
import org.cyclonedx.model.Pedigree;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.Service;
import org.cyclonedx.model.Tool;
import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Identity.Field;
import org.cyclonedx.model.license.Expression;
import org.cyclonedx.model.metadata.ToolInformation;
import org.cyclonedx.parsers.JsonParser;
import org.jboss.pnc.api.deliverablesanalyzer.dto.LicenseInfo;
import org.jboss.pnc.build.finder.core.SpdxLicenseUtils;
import org.jboss.pnc.common.Strings;
import org.jboss.pnc.dto.Artifact;
import org.jboss.pnc.dto.Build;
import org.jboss.pnc.dto.DeliverableAnalyzerOperation;
import org.jboss.pnc.dto.response.AnalyzedArtifact;
import org.jboss.pnc.dto.response.AnalyzedDistribution;
import org.jboss.pnc.restclient.util.ArtifactUtil;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.Constants;
import org.jboss.sbomer.core.features.sbom.config.Config;
import org.jboss.sbomer.core.features.sbom.config.OperationConfig;
import org.jboss.sbomer.core.features.sbom.config.PncBuildConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.ProductConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.RedHatProductProcessorConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;

public class SbomUtils {
    public static final String PROTOCOL = "https://";

    public static final String COMPONENT_LICENSE_ACKNOWLEDGEMENT = "concluded";

    public static final String EVIDENCE_LICENSE_ACKNOWLEDGEMENT = "declared";

    private static class HashAlgorithmMapping<T> {
        final Hash.Algorithm algorithm;
        final Function<T, String> getter; // Function takes T and returns String

        HashAlgorithmMapping(Hash.Algorithm algorithm, Function<T, String> getter) {
            this.algorithm = algorithm;
            this.getter = getter;
        }
    }

    private static final List<HashAlgorithmMapping<AnalyzedDistribution>> DIST_HASH_DEFINITIONS = List.of(
            new HashAlgorithmMapping<>(Hash.Algorithm.MD5, AnalyzedDistribution::getMd5),
            new HashAlgorithmMapping<>(Hash.Algorithm.SHA1, AnalyzedDistribution::getSha1),
            new HashAlgorithmMapping<>(Hash.Algorithm.SHA_256, AnalyzedDistribution::getSha256));

    private SbomUtils() {
        // This is a utility class
    }

    private static final Logger log = LoggerFactory.getLogger(SbomUtils.class);
    private static final Pattern gitProtocolPattern = Pattern.compile("git@(.+):(.+)", Pattern.CASE_INSENSITIVE);

    public static Version schemaVersion() {
        return Version.VERSION_16;
    }

    public static Bom createBom() {
        try {
            BomJsonGenerator generator = BomGeneratorFactory.createJson(schemaVersion(), new Bom());
            return new JsonParser().parse(generator.toJsonString().getBytes());
        } catch (ParseException | GeneratorException e) {
            log.error("Unable to create a new Bom", e);
            return null;
        }
    }

    public static Component createComponent(Component component) {
        return createComponent(
                component.getGroup(),
                component.getName(),
                component.getVersion(),
                component.getDescription(),
                component.getPurl(),
                component.getType());
    }

    public static Component createComponent(
            String group,
            String name,
            String version,
            String description,
            String purl,
            Type type) {

        Component component = new Component();

        if (!Strings.isEmpty(group)) {
            component.setGroup(group);
        }
        if (!Strings.isEmpty(name)) {
            component.setName(name);
        }
        if (!Strings.isEmpty(version)) {
            component.setVersion(version);
        }
        if (!Strings.isEmpty(purl)) {
            component.setBomRef(purl);
            component.setPurl(purl);
        }
        if (type != null) {
            component.setType(type);
        }
        if (!Strings.isEmpty(description)) {
            component.setDescription(description);
        }
        return component;
    }

    private static void setCoordinates(Component component, Artifact artifact) {
        switch (artifact.getTargetRepository().getRepositoryType()) {
            case NPM: {
                NpmPackageRef coordinates = ArtifactUtil.parseNPMCoordinates(artifact);
                String[] scopeName = coordinates.getName().split("/");
                if (scopeName.length == 2) {
                    component.setGroup(scopeName[0]);
                    component.setName(scopeName[1]);
                } else if (scopeName.length == 1) {
                    component.setName(scopeName[0]);
                } else {
                    log.warn(
                            "Unexpected number of slashes in NPM artifact name {}, using it fully",
                            coordinates.getName());
                    component.setName(coordinates.getName());
                }
                component.setVersion(coordinates.getVersionString());
                break;
            }
            case MAVEN: {
                SimpleArtifactRef coordinates = ArtifactUtil.parseMavenCoordinates(artifact);
                component.setGroup(coordinates.getGroupId());
                component.setName(coordinates.getArtifactId());
                component.setVersion(coordinates.getVersionString());
                break;
            }
            default: {
                component.setName(artifact.getFilename());
            }
        }
    }

    public static Component setPncBuildMetadata(Component component, Build pncBuild, String pncApiUrl) {
        if (pncBuild == null) {
            return component;
        }

        addExternalReference(
                component,
                ExternalReference.Type.BUILD_SYSTEM,
                PROTOCOL + pncApiUrl + "/pnc-rest/v2/builds/" + pncBuild.getId(),
                SBOM_RED_HAT_PNC_BUILD_ID);

        addExternalReference(
                component,
                ExternalReference.Type.BUILD_META,
                pncBuild.getEnvironment().getSystemImageRepositoryUrl() + "/"
                        + pncBuild.getEnvironment().getSystemImageId(),
                SBOM_RED_HAT_ENVIRONMENT_IMAGE);

        if (!hasExternalReference(component, ExternalReference.Type.VCS)) {
            addExternalReference(
                    component,
                    ExternalReference.Type.VCS,
                    pncBuild.getScmRepository().getExternalUrl(),
                    "");
        }

        addPedigreeCommit(component, pncBuild.getScmUrl() + "#" + pncBuild.getScmTag(), pncBuild.getScmRevision());

        // If the SCM repository is not internal and a commitID was computed, add the pedigree.
        if (!Strings.isEmpty(pncBuild.getScmRepository().getExternalUrl())
                && pncBuild.getScmBuildConfigRevisionInternal() != null
                && !Boolean.TRUE.equals(pncBuild.getScmBuildConfigRevisionInternal())
                && pncBuild.getScmBuildConfigRevision() != null) {

            addPedigreeCommit(
                    component,
                    pncBuild.getScmRepository().getExternalUrl() + "#"
                            + pncBuild.getBuildConfigRevision().getScmRevision(),
                    pncBuild.getScmBuildConfigRevision());
        }

        return component;
    }

    public static Component setArtifactMetadata(Component component, Artifact artifact, String pncApiUrl) {
        if (artifact == null) {
            return component;
        }

        addExternalReference(
                component,
                ExternalReference.Type.BUILD_SYSTEM,
                PROTOCOL + pncApiUrl + "/pnc-rest/v2/artifacts/" + artifact.getId(),
                SBOM_RED_HAT_PNC_ARTIFACT_ID);
        return component;
    }

    public static Component setPncOperationMetadata(
            Component component,
            DeliverableAnalyzerOperation operation,
            String pncApiUrl) {
        if (operation != null) {

            addExternalReference(
                    component,
                    ExternalReference.Type.BUILD_SYSTEM,
                    PROTOCOL + pncApiUrl + "/pnc-rest/v2/operations/deliverable-analyzer/" + operation.getId(),
                    SBOM_RED_HAT_PNC_OPERATION_ID);
        }

        return component;
    }

    // FIXME: 'Optional<String>' used as type for parameter 'source'
    public static Component setBrewBuildMetadata(
            Component component,
            String brewBuildId,
            Optional<String> source,
            String kojiApiUrl) {
        if (brewBuildId != null) {

            addExternalReference(
                    component,
                    ExternalReference.Type.BUILD_SYSTEM,
                    kojiApiUrl + "/buildinfo?buildID=" + brewBuildId,
                    SBOM_RED_HAT_BREW_BUILD_ID);

            if (source.isPresent()) {
                String scmSource = source.get();

                if (!hasExternalReference(component, ExternalReference.Type.VCS)) {
                    addExternalReference(component, ExternalReference.Type.VCS, scmSource, "");
                }

                int hashIndex = scmSource.lastIndexOf('#');
                if (hashIndex != -1) {
                    String commit = scmSource.substring(hashIndex + 1);
                    addPedigreeCommit(component, scmSource, commit);
                }
            }
        }
        return component;
    }

    public static void setProductMetadata(Component component, OperationConfig config) {
        Optional.ofNullable(config.getProduct())
                .map(ProductConfig::getProcessors)
                .ifPresent(
                        processors -> processors.stream()
                                .filter(RedHatProductProcessorConfig.class::isInstance)
                                .map(RedHatProductProcessorConfig.class::cast)
                                .forEach(processorConfig -> {
                                    addPropertyIfMissing(
                                            component,
                                            PROPERTY_ERRATA_PRODUCT_NAME,
                                            processorConfig.getErrata().getProductName());
                                    addPropertyIfMissing(
                                            component,
                                            PROPERTY_ERRATA_PRODUCT_VERSION,
                                            processorConfig.getErrata().getProductVersion());
                                    addPropertyIfMissing(
                                            component,
                                            PROPERTY_ERRATA_PRODUCT_VARIANT,
                                            processorConfig.getErrata().getProductVariant());
                                }));
    }

    public static Optional<URI> getNormalizedUrl(String url) {
        if (Strings.isEmpty(url)) {
            return Optional.empty();
        }

        try {
            return Optional.of(new URI(url).normalize());
        } catch (URISyntaxException e) {
            log.error("Failed to normalize URL '{}': {}", url, e.getMessage(), e);
            return Optional.empty();
        }
    }

    private static void addLicenseEvidence(Component component, List<LicenseInfo> licenseInfos) {
        if (licenseInfos.isEmpty()) {
            return;
        }

        Evidence evidence = new Evidence();
        LicenseChoice licenseChoice = new LicenseChoice();
        List<String> spdxLicenseIds = licenseInfos.stream()
                .map(LicenseInfo::getSpdxLicenseId)
                .filter(spdxLicenseId -> !SpdxLicenseUtils.isUnknownLicenseId(spdxLicenseId))
                .toList();

        if (SpdxLicenseUtils.containsExpression(spdxLicenseIds)) {
            Expression expression = new Expression();
            String value = SpdxLicenseUtils.toExpression(spdxLicenseIds);
            expression.setValue(value);
            expression.setAcknowledgement(EVIDENCE_LICENSE_ACKNOWLEDGEMENT);
            licenseChoice.setExpression(expression);
            evidence.setLicenses(licenseChoice);
            component.setEvidence(evidence);
            return;
        }

        licenseChoice.setLicenses(
                licenseInfos.stream()
                        .filter(licenseInfo -> !SpdxLicenseUtils.isUnknownLicenseId(licenseInfo.getSpdxLicenseId()))
                        .map(licenseInfo -> {
                            License license = new License();
                            license.setId(licenseInfo.getSpdxLicenseId());
                            license.setAcknowledgement(EVIDENCE_LICENSE_ACKNOWLEDGEMENT);
                            String sourceUrl = licenseInfo.getSourceUrl();

                            if (!Strings.isEmpty(sourceUrl)) {
                                Property sourceProperty = new Property();
                                sourceProperty.setName("sourceUrl");
                                sourceProperty.setValue(sourceUrl);
                                license.setProperties(List.of(sourceProperty));
                            }

                            String url = licenseInfo.getUrl();
                            Optional<URI> optionalURI = getNormalizedUrl(url);

                            if (optionalURI.isPresent()) {
                                URI uri = optionalURI.get();
                                String normalizedUri = uri.toASCIIString();

                                if (uri.isAbsolute()) {
                                    license.setUrl(normalizedUri);
                                }
                            }

                            return license;
                        })
                        .toList());
        evidence.setLicenses(licenseChoice);
        component.setEvidence(evidence);
    }

    public static List<Hash> getHashesFromAnalyzedDistribution(AnalyzedDistribution analyzedDistribution) {
        List<Hash> hashes = new ArrayList<>();

        if (analyzedDistribution == null) {
            return hashes;
        }

        // Use our pre-defined Algo to getter mapper here (DIST_HASH_DEFINTIONS)
        for (HashAlgorithmMapping m : DIST_HASH_DEFINITIONS) {

            // eg. Call analyzedArtifact.getDistribution.getSha256 and return a cdx Hash of type SHA_256
            String hashValue = (String) m.getter.apply(analyzedDistribution);

            if (Objects.nonNull(hashValue)) {
                hashes.add(new Hash(m.algorithm, hashValue));
            }
        }
        return hashes;
    }

    public static Component createComponent(AnalyzedArtifact analyzedArtifact, Scope scope, Type type) {
        Component component = createComponent(analyzedArtifact.getArtifact(), scope, type);
        Map<String, List<LicenseInfo>> uniqueLicensesMap = analyzedArtifact.getLicenses()
                .stream()
                .filter(licenseInfo -> !SpdxLicenseUtils.isUnknownLicenseId(licenseInfo.getSpdxLicenseId()))
                .collect(Collectors.groupingBy(LicenseInfo::getSpdxLicenseId));
        LicenseChoice licenseChoice = new LicenseChoice();
        List<String> spdxLicenseIds = uniqueLicensesMap.keySet().stream().sorted().toList();

        if (SpdxLicenseUtils.containsExpression(spdxLicenseIds)) {
            Expression expression = new Expression();
            String value = SpdxLicenseUtils.toExpression(spdxLicenseIds);
            expression.setValue(value);
            expression.setAcknowledgement(COMPONENT_LICENSE_ACKNOWLEDGEMENT);
            licenseChoice.setExpression(expression);
        } else {
            licenseChoice.setLicenses(spdxLicenseIds.stream().map(spdxLicenseId -> {
                License license = new License();
                license.setId(spdxLicenseId);
                license.setAcknowledgement(COMPONENT_LICENSE_ACKNOWLEDGEMENT);
                return license;
            }).toList());
        }

        component.setLicenses(licenseChoice);
        Set<Map.Entry<String, List<LicenseInfo>>> entries = uniqueLicensesMap.entrySet();

        for (Map.Entry<String, List<LicenseInfo>> entry : entries) {
            String spdxLicenseId = entry.getKey();
            List<LicenseInfo> licenseInfos = entry.getValue()
                    .stream()
                    .sorted(Comparator.comparing(LicenseInfo::getSpdxLicenseId))
                    .toList();
            addLicenseEvidence(component, licenseInfos);
            licenseInfos.stream()
                    .map(licenseInfo -> getNormalizedUrl(licenseInfo.getUrl()))
                    .forEach(
                            optionalURI -> optionalURI.ifPresent(
                                    uri -> addExternalReference(
                                            component,
                                            ExternalReference.Type.LICENSE,
                                            uri.toASCIIString(),
                                            spdxLicenseId)));
        }
        return component;
    }

    public static Component createComponent(Artifact artifact, Scope scope, Type type) {
        Component component = new Component();
        setCoordinates(component, artifact);
        component.setScope(scope);
        component.setType(type);
        component.setPurl(artifact.getPurl());
        component.setBomRef(artifact.getPurl());

        List<Hash> hashes = new ArrayList<>();
        hashes.add(new Hash(Algorithm.MD5, artifact.getMd5()));
        hashes.add(new Hash(Algorithm.SHA1, artifact.getSha1()));
        hashes.add(new Hash(Algorithm.SHA_256, artifact.getSha256()));
        component.setHashes(hashes);

        if ((component.getVersion() != null && RhVersionPattern.isRhVersion(component.getVersion()))
                || (component.getPurl() != null && RhVersionPattern.isRhPurl(component.getPurl()))) {
            SbomUtils.setPublisher(component);
            SbomUtils.setSupplier(component);
            SbomUtils.addMrrc(component);
        }
        return component;
    }

    public static Metadata createDefaultSbomerMetadata(Component component, String version) {
        Metadata metadata = new Metadata();
        metadata.setComponent(component);
        metadata.setTimestamp(Date.from(Instant.now()));

        LicenseChoice licenseChoice = new LicenseChoice();
        License license = new License();
        license.setId(SBOMER_LICENSE_ID);
        licenseChoice.setLicenses(List.of(license));
        metadata.setLicenses(licenseChoice);

        Property vcs = new Property();
        vcs.setName(ExternalReference.Type.VCS.name());
        vcs.setValue(SBOMER_GIT_URL);
        Property website = new Property();
        website.setName(ExternalReference.Type.WEBSITE.name());
        website.setValue(SBOMER_WEBSITE);
        metadata.setProperties(List.of(vcs, website));

        // Set legacy tool info
        if (Version.VERSION_14.equals(schemaVersion())) {
            metadata.setTools(List.of(createTool(version)));
        } else if (Version.VERSION_14.getVersion() < schemaVersion().getVersion()) {
            metadata.setToolChoice(createToolInformation(version));
        }

        return metadata;
    }

    public static List<ParseException> validate(JsonNode jsonNode) throws IOException {
        return new JsonParser().validate(
                jsonNode.isTextual() ? jsonNode.textValue().getBytes() : jsonNode.toString().getBytes(),
                schemaVersion());
    }

    public static Tool createTool(String version) { // NOSONAR: Tool is deprecated, but this is for legacy support
        Tool tool = new Tool(); // NOSONAR: Tool is deprecated, but this is for legacy support
        tool.setName(SBOMER_NAME);
        tool.setVendor(PUBLISHER);
        if (version != null) {
            tool.setVersion(version);
        }

        return tool;
    }

    /**
     * <p>
     * For a given {@link Bom} update all references for a given purl within the manifest from {@code oldPurl} to
     * {@code newPurl}.
     * </p>
     *
     * <p>
     * This includes traversing through components as well as dependencies.
     * </p>
     *
     * <p>
     * In some cases, this will lead to duplicate components and dependencies. This process ensures that there are no
     * duplicates as well.
     * </p>
     *
     * @param bom the BOM
     * @param oldPurl the old purl
     * @param newPurl the new purl
     */
    public static void updatePurl(Bom bom, String oldPurl, String newPurl) {
        // Update main component's purl
        if (updatePurl(bom.getMetadata().getComponent(), oldPurl, newPurl)) {
            updateBomRef(bom, bom.getMetadata().getComponent(), oldPurl, newPurl);
        }

        // If we have any components (we really should!) then update these purls as well
        if (bom.getComponents() != null) {
            // Update all components' purls (if needed)
            bom.getComponents().forEach(c -> {
                if (updatePurl(c, oldPurl, newPurl)) {
                    updateBomRef(bom, c, oldPurl, newPurl);
                }
            });
        }
    }

    /**
     * Updates the purl for the given component if it matches the old purl.
     *
     * @param component the component
     * @param oldPurl the old purl
     * @param newPurl the new purl
     * @return {@code true} if the purl was updated, {@code false} otherwise
     */
    public static boolean updatePurl(Component component, String oldPurl, String newPurl) {
        if (component.getPurl().equals(oldPurl)) {
            component.setPurl(newPurl);

            return true;
        }

        return false;
    }

    /**
     * Updates the bom-ref for the given component, and update the refs in the dependency hierarchy, looking for nested
     * dependencies and provides.
     *
     * @param component the component to update the bom-ref for
     * @param newRef the new reference
     */
    public static void updateBomRef(Bom bom, Component component, String oldRef, String newRef) {
        // Update the BOM reference of the component.
        // There might be cases (mainly for components detected by Syft) where the same purl is duplicated across
        // components (which have different bom-refs). So, we need to check if there are not already dependencies having
        // the bom-ref equals to the new purl before updating it. Otherwise, we would have bom validation errors.
        if (oldRef.equals(component.getBomRef())
                && !bom.getDependencies().stream().map(Dependency::getRef).toList().contains(newRef)) {

            component.setBomRef(newRef);

            // Recursively update the dependencies in the BOM
            if (bom.getDependencies() != null) {
                List<Dependency> updatedDependencies = new ArrayList<>(bom.getDependencies().size());
                for (Dependency dependency : bom.getDependencies()) {
                    Dependency updatedDependency = updateDependencyRef(dependency, oldRef, newRef);
                    updatedDependencies.add(updatedDependency);
                }
                bom.setDependencies(updatedDependencies);
            }
        }
    }

    public static Dependency updateDependencyRef(Dependency dependency, String oldRef, String newRef) {
        // If the current dependency has the oldRef, replace it with newRef
        if (dependency.getRef().equals(oldRef)) {
            Dependency updatedDependency = new Dependency(newRef);
            updatedDependency.setDependencies(dependency.getDependencies());
            updatedDependency.setProvides(dependency.getProvides());

            // Replace the old dependency with the updated one
            dependency = updatedDependency;
        }

        // Recursively update sub-dependencies
        if (dependency.getDependencies() != null) {
            List<Dependency> subDependencies = new ArrayList<>(dependency.getDependencies().size());
            for (Dependency subDependency : dependency.getDependencies()) {
                Dependency updatedSubDependency = updateDependencyRef(subDependency, oldRef, newRef);
                subDependencies.add(updatedSubDependency);
            }
            dependency.setDependencies(subDependencies);
        }

        // Recursively update provided dependencies
        if (dependency.getProvides() != null) {
            List<Dependency> subProvides = new ArrayList<>(dependency.getProvides().size());
            for (Dependency subProvide : dependency.getProvides()) {
                Dependency updatedSubProvide = updateDependencyRef(subProvide, oldRef, newRef);
                subProvides.add(updatedSubProvide);
            }
            dependency.setProvides(subProvides);
        }

        return dependency;
    }

    public static Dependency updateDependencyRef(Dependency dependency, Pattern pattern, String newRef) {
        // If the current dependency ref matches pattern, replace it with newRef
        if (pattern.matcher(dependency.getRef()).matches()) {
            Dependency updatedDependency = new Dependency(newRef);
            updatedDependency.setDependencies(dependency.getDependencies());
            updatedDependency.setProvides(dependency.getProvides());

            // Replace the old dependency with the updated one
            dependency = updatedDependency;
        }

        // Recursively update sub-dependencies
        if (dependency.getDependencies() != null) {
            List<Dependency> subDependencies = new ArrayList<>(dependency.getDependencies().size());
            for (Dependency subDependency : dependency.getDependencies()) {
                Dependency updatedSubDependency = updateDependencyRef(subDependency, pattern, newRef);
                subDependencies.add(updatedSubDependency);
            }
            dependency.setDependencies(subDependencies);
        }

        // Recursively update provided dependencies
        if (dependency.getProvides() != null) {
            List<Dependency> subProvides = new ArrayList<>(dependency.getProvides().size());
            for (Dependency subProvide : dependency.getProvides()) {
                Dependency updatedSubProvide = updateDependencyRef(subProvide, pattern, newRef);
                subProvides.add(updatedSubProvide);
            }
            dependency.setProvides(subProvides);
        }
        return dependency;
    }

    public static ToolInformation createToolInformation(String version) {
        ToolInformation information = new ToolInformation();
        Service service = new Service();
        service.setName(SBOMER_NAME);
        if (version != null) {
            service.setVersion(version);
        }
        OrganizationalEntity provider = new OrganizationalEntity();
        provider.setName(PUBLISHER);
        provider.setUrls(List.of(SUPPLIER_URL));
        service.setProvider(provider);
        LicenseChoice licenseChoice = new LicenseChoice();
        License license = new License();
        license.setId(SBOMER_LICENSE_ID);
        license.setAcknowledgement(EVIDENCE_LICENSE_ACKNOWLEDGEMENT);
        license.setUrl(SBOMER_LICENSE_URL);
        licenseChoice.setLicenses(List.of(license));
        service.setLicenses(licenseChoice);
        ExternalReference upstreamSCM = new ExternalReference();
        upstreamSCM.setType(org.cyclonedx.model.ExternalReference.Type.VCS);
        upstreamSCM.setUrl(SBOMER_GIT_URL);
        service.addExternalReference(upstreamSCM);
        ExternalReference upstreamWebsite = new ExternalReference();
        upstreamWebsite.setType(org.cyclonedx.model.ExternalReference.Type.WEBSITE);
        upstreamWebsite.setUrl(SBOMER_WEBSITE);
        service.addExternalReference(upstreamWebsite);
        information.setServices(List.of(service));
        return information;
    }

    public static Dependency createDependency(String ref) {
        return new Dependency(ref);
    }

    public static boolean hasHash(Component component, Algorithm algorithm) {
        return getHash(component, algorithm).isPresent();
    }

    public static Optional<String> getHash(Component component, Algorithm algorithm) {
        List<Hash> hashes;

        if (component.getHashes() != null) {
            hashes = component.getHashes();
        } else {
            if (component.getExternalReferences() == null) {
                return Optional.empty();
            }

            Optional<ExternalReference> buildMetaRefOpt = component.getExternalReferences()
                    .stream()
                    .filter(r -> r.getType().equals(ExternalReference.Type.BUILD_META))
                    .findFirst();

            if (buildMetaRefOpt.isEmpty()) {
                return Optional.empty();
            }

            hashes = buildMetaRefOpt.get().getHashes();
        }

        return hashes.stream()
                .filter(h -> h.getAlgorithm().equalsIgnoreCase(algorithm.getSpec()))
                .map(Hash::getValue)
                .findFirst();
    }

    public static void addHashIfMissing(Component component, String hash, Algorithm algorithm) {

        List<Hash> hashes = new ArrayList<>();
        if (component.getHashes() != null) {
            hashes.addAll(component.getHashes());
        }
        // If there isn't already the same algorithm present (do not override), add it
        if (hashes.stream().noneMatch(h -> h.getAlgorithm().equalsIgnoreCase(algorithm.getSpec()))) {
            hashes.add(new Hash(algorithm.getSpec(), hash));
            component.setHashes(hashes);
        }
    }

    public static void addHashIfMissing(Component component, String hash, String algorithmSpec) {
        addHashIfMissing(component, hash, Algorithm.fromSpec(algorithmSpec));
    }

    public static void addProperty(Component component, String key, String value) {
        log.debug("addProperty {}: {}", key, value);
        List<Property> properties = new ArrayList<>();
        if (component.getProperties() != null) {
            properties.addAll(component.getProperties());
        }
        Property property = new Property();
        property.setName(key);
        property.setValue(value != null ? value : "");
        properties.add(property);
        component.setProperties(properties);
    }

    public static void addProperty(Metadata metadata, String key, String value) {
        log.debug("addProperty {}: {}", key, value);
        List<Property> properties = new ArrayList<>();
        if (metadata.getProperties() != null) {
            properties.addAll(metadata.getProperties());
        }
        Property property = new Property();
        property.setName(key);
        property.setValue(value != null ? value : "");
        properties.add(property);
        metadata.setProperties(properties);
    }

    /**
     * <p>
     * Adds a property of a given name in case it's not already there.
     * </p>
     *
     * @param component The {@link Component} to add the property to.
     * @param property The name of the property.
     * @param value The value of the property.
     */
    public static void addPropertyIfMissing(Component component, String property, String value) {
        if (component == null) {
            return;
        }
        Optional<Property> p = findPropertyWithName(property, component.getProperties());
        if (p.isEmpty()) {
            log.info("Adding {} property with value: {}", property, value);
            addProperty(component, property, value);
        } else {
            log.debug("Property {} already exist, value: {}", property, p.get().getValue());
        }
    }

    /**
     * <p>
     * Adds a property of a given name in case it's not already there.
     * </p>
     *
     * @param metadata The {@link Metadata} to add the property to.
     * @param property The name of the property.
     * @param value The value of the property.
     */
    public static void addPropertyIfMissing(Metadata metadata, String property, String value) {
        if (metadata == null) {
            return;
        }
        Optional<Property> p = findPropertyWithName(property, metadata.getProperties());
        if (p.isEmpty()) {
            log.info("Adding {} property with value: {}", property, value);
            addProperty(metadata, property, value);
        } else {
            log.debug("Property {} already exist, value: {}", property, p.get().getValue());
        }
    }

    public static void removeProperty(Component component, String name) {
        if (component.getProperties() != null) {
            Optional<Property> property = component.getProperties()
                    .stream()
                    .filter(p -> p.getName().equals(name))
                    .findFirst();
            property.ifPresent(value -> component.getProperties().remove(value));
        }
    }

    public static Optional<Component> findComponentWithPurl(String purl, Bom bom) {
        return bom.getComponents().stream().filter(c -> c.getPurl().equals(purl)).findFirst();
    }

    public static boolean hasProperty(Component component, String property) {
        return component.getProperties() != null
                && component.getProperties().stream().anyMatch(c -> c.getName().equals(property));
    }

    public static Optional<Property> findPropertyWithNameInComponent(String propertyName, Component component) {
        if (component == null) {
            return Optional.empty();
        }

        return findPropertyWithName(propertyName, component.getProperties());
    }

    public static Optional<Property> findPropertyWithName(String propertyName, List<Property> properties) {
        if (properties == null || properties.isEmpty()) {
            return Optional.empty();
        }

        return properties.stream().filter(p -> p.getName().equals(propertyName)).findFirst();
    }

    public static boolean hasExternalReference(Component c, ExternalReference.Type type) {
        return !getExternalReferences(c, type).isEmpty();
    }

    public static boolean hasExternalReference(Component c, ExternalReference.Type type, String comment) {
        return !getExternalReferences(c, type, comment).isEmpty();
    }

    public static List<ExternalReference> getExternalReferences(Component c, ExternalReference.Type type) {
        return Optional.ofNullable(c.getExternalReferences())
                .stream()
                .flatMap(Collection::stream)
                .filter(ref -> ref.getType().equals(type))
                .toList();
    }

    public static List<ExternalReference> getExternalReferences(
            Component c,
            ExternalReference.Type type,
            String comment) {

        return Optional.ofNullable(c.getExternalReferences())
                .stream()
                .flatMap(Collection::stream)
                .filter(ref -> ref.getType().equals(type))
                .filter(ref -> Objects.equals(ref.getComment(), comment))
                .toList();
    }

    public static void addExternalReference(Component c, ExternalReference.Type type, String url, String comment) {
        if (Strings.isEmpty(url)) {
            return;
        }

        List<ExternalReference> externalRefs = new ArrayList<>();
        if (c.getExternalReferences() != null) {
            externalRefs.addAll(c.getExternalReferences());
        }

        ExternalReference reference = Optional.of(externalRefs)
                .stream()
                .flatMap(Collection::stream)
                .filter(ref -> ref.getType().equals(type))
                .filter(ref -> Objects.equals(ref.getComment(), comment))
                .findFirst()
                .orElse(null);

        if (reference == null) {
            reference = new ExternalReference();
            reference.setType(type);
            externalRefs.add(reference);
        }

        reference.setUrl(url);
        reference.setComment(comment);

        c.setExternalReferences(externalRefs);
    }

    public static void addPedigreeCommit(Component c, String url, String uid) {
        if (!Strings.isEmpty(url)) {

            Matcher matcher = gitProtocolPattern.matcher(url);

            if (matcher.find()) {
                log.debug(
                        "Found URL to be added as pedigree commit with the 'git@' protocol: '{}', trying to convert it into 'https://'",
                        url);

                url = PROTOCOL + matcher.group(1) + "/" + matcher.group(2);

                log.debug("Converted into: '{}'", url);

            }

            Pedigree pedigree = c.getPedigree() == null ? new Pedigree() : c.getPedigree();
            List<Commit> commits = new ArrayList<>();
            if (pedigree.getCommits() != null) {
                commits.addAll(pedigree.getCommits());
            }

            Commit newCommit = new Commit();
            newCommit.setUid(uid);
            newCommit.setUrl(url);
            commits.add(newCommit);
            pedigree.setCommits(commits);

            c.setPedigree(pedigree);
        }
    }

    public static void setPublisher(Component c) {
        c.setPublisher(PUBLISHER);
    }

    public static void setSupplier(Component c) {
        OrganizationalEntity org = new OrganizationalEntity();
        org.setName(SUPPLIER_NAME);
        org.setUrls(List.of(SUPPLIER_URL));
        c.setSupplier(org);
    }

    public static void addMrrc(Component c) {
        List<ExternalReference> externalRefs = new ArrayList<>();
        if (c.getExternalReferences() != null) {
            externalRefs.addAll(c.getExternalReferences());
        }
        ExternalReference dist = null;
        for (ExternalReference r : externalRefs) {
            if (r.getType().equals(ExternalReference.Type.DISTRIBUTION)) {
                dist = r;
                break;
            }
        }
        if (dist == null) {
            dist = new ExternalReference();
            dist.setType(ExternalReference.Type.DISTRIBUTION);
            externalRefs.add(dist);
        }
        dist.setUrl(MRRC_URL);
        c.setExternalReferences(externalRefs);
    }

    /**
     * Converts the given CycloneDX {@link Bom} into a {@link JsonNode} object.
     *
     * @param bom The CycloneDX {@link Bom} to convert
     * @return {@link JsonNode} representation of the {@link Bom}.
     */
    public static JsonNode toJsonNode(Bom bom) {
        BomJsonGenerator generator = BomGeneratorFactory.createJson(SbomUtils.schemaVersion(), bom);
        return generator.toJsonNode();
    }

    /**
     * Converts the given CycloneDX {@link Bom} into a JSON {@link String} object.
     *
     * @param bom The CycloneDX {@link Bom} to convert
     * @return {@link String} representation of the {@link Bom}.
     * @throws GeneratorException if an error occurs during the conversion
     */
    public static String toJson(Bom bom) throws GeneratorException {
        BomJsonGenerator generator = BomGeneratorFactory.createJson(SbomUtils.schemaVersion(), bom);
        return generator.toJsonString();
    }

    /**
     * Converts the {@link JsonNode} into a CycloneDX {@link Bom} object.
     *
     * @param jsonNode The {@link JsonNode} to convert.
     * @return The converted {@link Bom} or <code>null</code> in case of troubles in converting it.
     */
    public static Bom fromJsonNode(JsonNode jsonNode) {
        if (jsonNode == null) {
            return null;
        }

        try {
            final String content = jsonNode.isTextual() ? jsonNode.textValue() : jsonNode.toString();
            return new JsonParser().parse(content.getBytes(UTF_8));
        } catch (ParseException e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    public static List<String> computeNVRFromContainerManifest(JsonNode jsonNode) {
        Bom bom = fromJsonNode(jsonNode);
        if (bom == null || !isNotEmpty(bom.getComponents())) {
            return List.of();
        }
        Component mainComponent = bom.getComponents().get(0);
        Property n = findPropertyWithNameInComponent(Constants.CONTAINER_PROPERTY_IMAGE_LABEL_COMPONENT, mainComponent)
                .orElse(null);
        Property v = findPropertyWithNameInComponent(Constants.CONTAINER_PROPERTY_IMAGE_LABEL_VERSION, mainComponent)
                .orElse(null);
        Property r = findPropertyWithNameInComponent(Constants.CONTAINER_PROPERTY_IMAGE_LABEL_RELEASE, mainComponent)
                .orElse(null);

        if (n != null && v != null && r != null) {
            return List.of(n.getValue(), v.getValue(), r.getValue());
        }

        return List.of();
    }

    public static void setEvidenceIdentities(Component c, Set<String> concludedValues, Field field) {
        List<Identity> identities = concludedValues.stream().map(concludedValue -> {
            Identity identity = new Identity();
            identity.setField(field);
            identity.setConcludedValue(concludedValue);
            return identity;
        }).toList();

        Evidence evidence = new Evidence();
        evidence.setIdentities(identities);
        c.setEvidence(evidence);
    }

    public static Bom fromPath(Path path) {
        try {
            return new JsonParser().parse(path.toFile());
        } catch (ParseException e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    public static void toPath(Bom bom, Path path) {
        try {
            Files.writeString(path, SbomUtils.toJson(bom));
        } catch (IOException | GeneratorException e) {
            log.error(e.getMessage(), e);
        }
    }

    public static Bom fromString(String bomStr) {
        try {
            return new JsonParser().parse(bomStr.getBytes(UTF_8));
        } catch (ParseException e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    /**
     * Converts the {@link JsonNode} into a runtime Config {@link Config} object.
     *
     * @param jsonNode The {@link JsonNode} to convert.
     * @return The converted {@link Config} or <code>null</code> in case of troubles in converting it.
     */
    public static PncBuildConfig fromJsonBuildConfig(JsonNode jsonNode) {
        if (jsonNode == null) {
            return null;
        }

        try {
            return ObjectMapperProvider.json()
                    .readValue(
                            jsonNode.isTextual() ? jsonNode.textValue().getBytes() : jsonNode.toString().getBytes(),
                            PncBuildConfig.class);
        } catch (IOException e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    /**
     * Converts the {@link JsonNode} into a runtime {@link OperationConfig} object.
     *
     * @param jsonNode The {@link JsonNode} to convert.
     * @return The converted {@link OperationConfig} or <code>null</code> in case of troubles in converting it.
     */
    public static OperationConfig fromJsonOperationConfig(JsonNode jsonNode) {
        if (jsonNode == null) {
            return null;
        }

        try {
            return ObjectMapperProvider.json()
                    .readValue(
                            jsonNode.isTextual() ? jsonNode.textValue().getBytes() : jsonNode.toString().getBytes(),
                            OperationConfig.class);
        } catch (IOException e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    /**
     * Converts the given config {@link Config} into a {@link JsonNode} object.
     *
     * @param config The config {@link Config} to convert
     * @return {@link JsonNode} representation of the {@link Config}.
     */
    public static JsonNode toJsonNode(Config config) {

        try {
            String configuration = ObjectMapperProvider.json()
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(config);
            return ObjectMapperProvider.json().readTree(configuration);
        } catch (JsonProcessingException e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    /**
     * Converts the given config {@link OperationConfig} into a {@link JsonNode} object.
     *
     * @param operationConfig The config {@link OperationConfig} to convert
     * @return {@link JsonNode} representation of the {@link OperationConfig}.
     */
    public static JsonNode toJsonNode(OperationConfig operationConfig) {

        try {
            String configuration = ObjectMapperProvider.json()
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(operationConfig);
            return ObjectMapperProvider.json().readTree(configuration);
        } catch (JsonProcessingException e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    /**
     * Converts the given string into a {@link JsonNode} object.
     *
     * @param jsonString The string to convert
     * @return {@link JsonNode} representation of the string.
     */
    public static JsonNode toJsonNode(String jsonString) {

        try {
            return ObjectMapperProvider.json().readTree(jsonString);
        } catch (JsonProcessingException e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    /**
     * Converts the given environment config {@link Map} into a {@link JsonNode} object.
     *
     * @param envConfig The environment config {@link Map} to convert
     * @return {@link JsonNode} representation of the {@link Map}.
     */
    public static JsonNode toJsonNode(Map<String, String> envConfig) {

        try {
            String configuration = ObjectMapperProvider.json()
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(envConfig);
            return ObjectMapperProvider.json().readTree(configuration);
        } catch (JsonProcessingException e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    /**
     * Given a raw {@link JsonNode}, converts it to a CycloneDX {@link Bom} object, and removes any Errata information
     * from the main component properties.
     *
     * @param jsonNode The {@link JsonNode} to convert.
     */
    public static JsonNode removeErrataProperties(JsonNode jsonNode) {
        Bom bom = fromJsonNode(jsonNode);
        removeErrataProperties(bom);
        return toJsonNode(bom);
    }

    /**
     * Removes any Errata information from the provided CycloneDX {@link Bom} object.
     *
     * @param bom The {@link Bom} containing the main component to be cleaned up from its Errata properties.
     */
    public static void removeErrataProperties(Bom bom) {
        if (bom != null && isNotEmpty(bom.getComponents())) {
            Component component = bom.getComponents().get(0);
            removeProperty(component, PROPERTY_ERRATA_PRODUCT_NAME);
            removeProperty(component, PROPERTY_ERRATA_PRODUCT_VERSION);
            removeProperty(component, PROPERTY_ERRATA_PRODUCT_VARIANT);
        }
    }

    /**
     * Creates a purl of OCI type for the image
     *
     * @param imageName the image name (can contain registry and repository)
     * @param imageDigest the image digest (sha)
     */
    public static String createContainerImageOCIPurl(String imageName, String imageDigest) {
        // Extract last fragment from the imageName (in case of nested repositories or registry)
        String repositoryName = Optional.ofNullable(imageName).map(repo -> {
            int lastSlashIndex = repo.lastIndexOf('/');
            return lastSlashIndex != -1 ? repo.substring(lastSlashIndex + 1) : repo;
        }).orElseThrow(() -> new IllegalArgumentException("Repository name is null"));

        if (imageDigest == null || imageDigest.isEmpty()) {
            throw new IllegalArgumentException("Image digest is null or empty");
        }

        try {
            return PackageURLBuilder.aPackageURL()
                    .withType("oci")
                    .withName(repositoryName)
                    .withVersion(imageDigest)
                    .build()
                    .toString();
        } catch (MalformedPackageURLException | IllegalArgumentException e) {
            log.warn(
                    "Error while creating summary PURL for imageName {} and imageDigest {}",
                    imageName,
                    imageDigest,
                    e);
            return null;
        }
    }

    /**
     * Creates a purl of OCI type for the image
     *
     * @param imageFullname the image fullname
     */
    public static String createContainerImageOCIPurl(String imageFullname) {
        if (imageFullname == null || imageFullname.isEmpty()) {
            throw new IllegalArgumentException("Image full name is null or empty");
        }

        String[] imageTokens = imageFullname.split("@");
        if (imageTokens.length != 2) {
            throw new IllegalArgumentException("Image full name has wrong format");
        }
        return createContainerImageOCIPurl(imageTokens[0], imageTokens[1]);
    }

    public static void addMissingSerialNumber(Bom bom) {
        if (bom.getSerialNumber() == null || bom.getSerialNumber().isEmpty()) {
            log.debug("Setting 'serialNumber' for manifest with purl '{}'", bom.getMetadata().getComponent().getPurl());

            try {
                String jsonContent = SbomUtils.toJson(bom);
                bom.setSerialNumber("urn:uuid:" + UUID.nameUUIDFromBytes(jsonContent.getBytes(UTF_8)));
            } catch (GeneratorException e) {
                log.warn("Could not generate serialNumber out of the manifest content, setting random UUID", e);
                bom.setSerialNumber(UUID.randomUUID().toString());
            }
        }
    }

    public static void addMissingContainerHash(Bom bom) {
        if (!isNotEmpty(bom.getComponents())) {
            return;
        }

        addMissingContainerHash(bom.getComponents().get(0));
    }

    public static void addMissingContainerHash(Component component) {
        if (component.getType() != Component.Type.CONTAINER) {
            return;
        }

        String[] versionTokens = component.getVersion().split(":");
        if (versionTokens.length < 2) {
            return;
        }
        Map<String, Hash.Algorithm> hashMap = Map.of(
                "md5",
                Hash.Algorithm.MD5,
                "sha1",
                Hash.Algorithm.SHA1,
                "sha256",
                Hash.Algorithm.SHA_256,
                "sha384",
                Hash.Algorithm.SHA_384,
                "sha512",
                Hash.Algorithm.SHA_512);

        hashMap.forEach((prefix, algorithm) -> {
            if (versionTokens[0].equalsIgnoreCase(prefix)) {
                addHashIfMissing(component, versionTokens[1], algorithm);
            }
        });
    }

    public static void addMissingMetadataSupplier(Bom bom) {
        if (bom == null) {
            return;
        }
        addMissingMetadataSupplier(bom.getMetadata());
    }

    private static void addMissingMetadataSupplier(Metadata metadata) {
        if (metadata == null) {
            return;
        }

        if (metadata.getSupplier() == null) {
            OrganizationalEntity org = new OrganizationalEntity();
            org.setName(SUPPLIER_NAME);
            org.setUrls(List.of(SUPPLIER_URL));
            metadata.setSupplier(org);
        }
    }

    /**
     *
     * @param component the component whose purl needs to be analyzed
     * @return true if the component has a valid purl, false if the purl is not valid even after a sanitization
     */
    public static boolean hasValidOrSanitizablePurl(Component component) {
        String purl = component.getPurl();

        // Try to validate the PURL first
        if (isValidPurl(purl)) {
            return true;
        }

        // Try to sanitize the PURL if invalid
        String sanitizedPurl = sanitizePurl(purl);
        if (sanitizedPurl != null) {
            component.setPurl(sanitizedPurl);
            log.debug("Sanitized purl {} to {}", purl, sanitizedPurl);
            return true;
        }

        // Attempt to rebuild the PURL if sanitization failed
        String rebuiltPurl = rebuildPurl(component);
        if (rebuiltPurl != null) {
            component.setPurl(rebuiltPurl);
            log.debug("Rebuilt purl {} to {}", purl, rebuiltPurl);
            return true;
        }

        return false;
    }

    public static boolean isValidPurl(String purl) {
        try {
            new PackageURL(purl);
            return true;
        } catch (MalformedPackageURLException e) {
            return false;
        }
    }

    public static String sanitizePurl(String purl) {
        try {
            return PurlSanitizer.sanitizePurl(purl);
        } catch (Exception e) {
            log.debug("Failed to sanitize purl {}", purl, e);
            return null;
        }
    }

    private static String rebuildPurl(Component component) {
        try {
            log.debug("Purl was not valid and could not be sanitized, trying to rebuild it!");
            return PurlRebuilder.rebuildPurlFromSyftComponent(component);
        } catch (MalformedPackageURLException e) {
            log.debug("Purl {} could not be rebuilt!", component.getPurl());
            return null;
        }
    }

    /**
     * Creates a new purl with the same name, namespace, subpath, type, version and qualifiers and add the specified
     * qualifier. If "redHatComponentsOnly" is true, add the qualifiers only if the component has a Red Hat version.
     * Finally, rebuild the purl to make sure it is valid and qualifiers are properly sorted.
     *
     * @param component the input component which has the purl to modify
     * @param qualifiers the Map with the qualifiers key-value
     * @param redHatComponentsOnly boolean, true if the qualifiers should be added only to components with the Red Hat
     *        version
     * @return The new validated purl as string.
     */
    public static String addQualifiersToPurlOfComponent(
            Component component,
            Map<String, String> qualifiers,
            boolean redHatComponentsOnly) {

        // In case this is not a RH artifact, do not update the purl
        if (redHatComponentsOnly && !RhVersionPattern.isRhVersion(component.getVersion())
                && !RhVersionPattern.isRhPurl(component.getPurl())) {
            return component.getPurl();
        }

        try {
            PackageURL purl = new PackageURL(component.getPurl());
            PackageURLBuilder builder = purl.toBuilder();
            qualifiers.forEach(builder::withQualifier);
            return builder.build().toString();
        } catch (MalformedPackageURLException | IllegalArgumentException e) {
            log.warn("Error while adding new qualifiers to component with purl {}", component.getPurl(), e);
            return component.getPurl();
        }
    }

    /**
     * Returns a TreeSet containing the component PURL and any PURL found among the evidence identities'
     * concludedValues.
     *
     * @param component the component
     * @return The TreeSet containing all the found PURLs
     */
    public static Set<String> getAllPurlsOfComponent(Component component) {

        if (component == null || component.getPurl() == null) {
            return Collections.emptySet();
        }

        SortedSet<String> allPurls = new TreeSet<>();
        allPurls.add(component.getPurl());

        if (component.getEvidence() == null || component.getEvidence().getIdentities() == null
                || component.getEvidence().getIdentities().isEmpty()) {
            return allPurls;
        }

        Set<String> purls = component.getEvidence()
                .getIdentities()
                .stream()
                .filter(identity -> Field.PURL.equals(identity.getField()))
                .map(Identity::getConcludedValue)
                .collect(Collectors.toSet());
        allPurls.addAll(purls);
        return allPurls;
    }

    /**
     * Verify if collection is populated
     *
     * @param collection the collection
     * @return {@code true} if collection is populated, {@code false} otherwise
     */
    public static <T> boolean isNotEmpty(Collection<T> collection) {
        return collection != null && !collection.isEmpty();
    }

    /**
     * Add missing components from one manifest to another
     *
     * @param targetComponents the target manifest components
     * @param sourceComponents the source manifest components
     */
    private static void addMissingComponents(List<Component> targetComponents, List<Component> sourceComponents) {
        Map<String, Component> mergedComponents = new HashMap<>();
        for (Component component : targetComponents) {
            // Skip if can't uniquely identify component
            if (bomRefExists(component)) {
                mergedComponents.put(component.getBomRef(), component);
            }
        }
        targetComponents.clear();
        for (Component component : sourceComponents) {
            // Skip if can't uniquely identify component
            if (bomRefExists(component)) {
                String bomRef = component.getBomRef();
                Component existingComponent = mergedComponents.get(bomRef);
                // Duplicate found, see if we have any missing subcomponents
                if (existingComponent != null) {
                    log.debug("Component (with bom-ref: '{}') already exists, adding missing subcomponents", bomRef);
                    List<Component> subComponents = component.getComponents();
                    // Pointless proceeding unless there are subcomponents from the source manifest
                    if (isNotEmpty(subComponents)) {
                        adjustEmptySubComponents(existingComponent);
                        addMissingComponents(existingComponent.getComponents(), subComponents);
                    }
                } else {
                    log.debug("Adding missing component (with bom-ref: '{}')", bomRef);
                    mergedComponents.put(bomRef, component);
                }
            }
        }
        targetComponents.addAll(mergedComponents.values());
    }

    /**
     * Add missing dependencies from one manifest to another
     *
     * @param targetDependencies the target manifest dependencies
     * @param sourceDependencies the source manifest dependencies
     */
    private static void addMissingDependencies(
            List<Dependency> targetDependencies,
            List<Dependency> sourceDependencies) {
        Map<String, Dependency> mergedDependencies = new HashMap<>();
        for (Dependency dependency : targetDependencies) {
            mergedDependencies.put(dependency.getRef(), dependency);
        }
        targetDependencies.clear();
        for (Dependency dependency : sourceDependencies) {
            String ref = dependency.getRef();
            Dependency existingDependency = mergedDependencies.get(ref);
            // Duplicate found, see if we have any missing sub-dependencies
            if (existingDependency != null) {
                log.debug("Dependency (with ref: '{}') already exists, adding missing sub-dependencies", ref);
                List<Dependency> subDependencies = dependency.getDependencies();
                // Pointless proceeding unless there are sub-dependencies from source manifest
                if (isNotEmpty(subDependencies)) {
                    adjustEmptySubDependencies(existingDependency);
                    addMissingDependencies(existingDependency.getDependencies(), subDependencies);
                }
                List<Dependency> subProvides = dependency.getProvides();
                // Pointless proceeding unless there are sub-provides from source manifest
                if (isNotEmpty(subProvides)) {
                    adjustEmptySubProvides(existingDependency);
                    addMissingDependencies(existingDependency.getProvides(), subProvides);
                }
            } else {
                log.debug("Adding missing dependency (with ref: '{}')", ref);
                mergedDependencies.put(ref, dependency);
            }
        }
        targetDependencies.addAll(mergedDependencies.values());
    }

    public static void addMissingComponentsAndDependencies(Bom targetBom, Bom sourceBom) {
        List<Component> sourcesComponents = sourceBom.getComponents();
        // Pointless proceeding unless there are components in source manifest
        if (isNotEmpty(sourcesComponents)) {
            addMissingComponents(targetBom.getComponents(), sourcesComponents);
        }
        List<Dependency> sourcesDependencies = sourceBom.getDependencies();
        // Pointless proceeding unless there are dependencies in source manifest
        if (isNotEmpty(sourcesDependencies)) {
            addMissingDependencies(targetBom.getDependencies(), sourcesDependencies);
        }
    }

    /**
     * Verify if component bom-ref exists
     *
     * @param component the component
     * @return {@code true} if bom-ref exists, {@code false} otherwise
     */
    private static boolean bomRefExists(Component component) {
        if (component.getBomRef() == null) {
            log.debug(
                    "Component (of type '{}', cpe: '{}') does not have bom-ref assigned, skipping",
                    component.getType(),
                    component.getCpe());
            return false;
        }
        return true;
    }

    /**
     * If the subcomponents are null, initialize an empty list
     *
     * @param component the component to adjust
     */
    private static void adjustEmptySubComponents(Component component) {
        if (component.getComponents() == null) {
            component.setComponents(new ArrayList<>());
        }
    }

    /**
     * If the sub-dependencies are null, initialize an empty list
     *
     * @param dependency the dependency to adjust
     */
    private static void adjustEmptySubDependencies(Dependency dependency) {
        if (dependency.getDependencies() == null) {
            dependency.setDependencies(new ArrayList<>());
        }
    }

    /**
     * If the sub-provides are null, initialize an empty list
     *
     * @param dependency the dependency to adjust
     */
    private static void adjustEmptySubProvides(Dependency dependency) {
        if (dependency.getProvides() == null) {
            dependency.setProvides(new ArrayList<>());
        }
    }

    /**
     * Find Golang standard library component in BOM
     *
     * @param bom the bom to search
     * @return The component
     */
    public static Component findGolangStandardLibraryComponent(Bom bom) {
        return bom.getComponents()
                .stream()
                .filter(c -> c.getBomRef().startsWith("pkg:golang/stdlib@"))
                .findFirst()
                .orElse(null);
    }

    /**
     * Read Cachito dependencies from sources metadata
     *
     * @param sourcesMetadataPath path to the sources metadata
     */
    public static Set<Map> readCachitoDependencies(Path sourcesMetadataPath) {
        Set<Map> cachitoDependencies = new HashSet<>();
        try {
            Map sourcesMetadata = ObjectMapperProvider.json().readValue(sourcesMetadataPath.toFile(), Map.class);
            List<Map> rootDependencies = (List<Map>) sourcesMetadata.get("dependencies");
            if (isNotEmpty(rootDependencies)) {
                log.debug("Reading Cachito root dependencies from sources metadata");
                cachitoDependencies.addAll(rootDependencies);
            }
            List<Map> packages = (List<Map>) sourcesMetadata.get("packages");
            if (packages != null) {
                for (Map pkg : packages) {
                    if (pkg != null && !pkg.isEmpty()) {
                        List<Map> dependencies = (List<Map>) pkg.get("dependencies");
                        if (dependencies != null) {
                            log.debug(
                                    "Reading Cachito package dependencies from sources metadata for {}",
                                    pkg.get("name"));
                            cachitoDependencies.addAll(dependencies);
                        }
                    }
                }
            }
        } catch (IOException e) {
            throw new ApplicationException("Could not read sources metadata", e);
        }
        return cachitoDependencies;
    }

    /**
     * Add any Golang standard library features detected in Cachito dependencies
     *
     * @param bom the bom to add standard library features to
     * @param standardLibraryComponent the standard library component
     * @param cachitoDependencies the Cachito dependencies
     */
    public static void addGolangStandardLibraryFeatures(
            Bom bom,
            Component standardLibraryComponent,
            Set<Map> cachitoDependencies) {
        // Pointless proceeding unless there are Cachito dependencies
        if (isNotEmpty(cachitoDependencies)) {
            List<Component> components = bom.getComponents();
            Map<String, Component> mergedComponents = new HashMap<>();
            for (Component component : components) {
                mergedComponents.put(component.getBomRef(), component);
            }
            components.clear();
            for (Map dep : cachitoDependencies) {
                // Only standard library features have missing version
                if (dep.get("version") == null && dep.get("type").equals("go-package")) {
                    String name = (String) dep.get("name");
                    String version = standardLibraryComponent.getVersion();
                    String purl = String.format("pkg:%s/%s@%s", PackageURL.StandardTypes.GOLANG, name, version);
                    if (mergedComponents.containsKey(purl)) {
                        log.debug(
                                "Golang standard library feature component (with bom-ref: '{}') already exists, skipping",
                                purl);
                    } else {
                        log.debug("Adding Golang standard library feature component (with bom-ref: '{}')", purl);
                        Component component = createComponent(null, name, version, null, purl, Component.Type.LIBRARY);
                        addProperty(component, CONTAINER_PROPERTY_SYFT_PREFIX + PACKAGE_LANGUAGE, "go");
                        mergedComponents.put(purl, component);
                    }
                }
            }
            components.addAll(mergedComponents.values());
        }
    }
}
