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
package org.jboss.sbomer.cli.feature.sbom.adjuster;

import static org.jboss.sbomer.core.features.sbom.Constants.CONTAINER_PROPERTY_IMAGE_LABELS_PREFIX;
import static org.jboss.sbomer.core.features.sbom.Constants.CONTAINER_PROPERTY_IMAGE_LABEL_MANTAINER;
import static org.jboss.sbomer.core.features.sbom.Constants.CONTAINER_PROPERTY_IMAGE_LABEL_RELEASE;
import static org.jboss.sbomer.core.features.sbom.Constants.CONTAINER_PROPERTY_IMAGE_LABEL_VENDOR;
import static org.jboss.sbomer.core.features.sbom.Constants.CONTAINER_PROPERTY_IMAGE_LABEL_VERSION;
import static org.jboss.sbomer.core.features.sbom.Constants.CONTAINER_PROPERTY_LOCATION_PATH_PREFIX;
import static org.jboss.sbomer.core.features.sbom.Constants.CONTAINER_PROPERTY_METADATA_VIRTUALPATH_PREFIX;
import static org.jboss.sbomer.core.features.sbom.Constants.CONTAINER_PROPERTY_PACKAGE_LANGUAGE_PREFIX;
import static org.jboss.sbomer.core.features.sbom.Constants.CONTAINER_PROPERTY_PACKAGE_TYPE_PREFIX;
import static org.jboss.sbomer.core.features.sbom.Constants.CONTAINER_PROPERTY_SYFT_PREFIX;
import static org.jboss.sbomer.core.features.sbom.Constants.CONTAINER_PROPERTY_SYFT_REPLACEMENT_PREFIX;
import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.addMissingContainerHash;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Property;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.Constants;
import org.jboss.sbomer.core.features.sbom.config.SyftImageConfig;
import org.jboss.sbomer.core.features.sbom.enums.GeneratorType;
import org.jboss.sbomer.core.features.sbom.koji.RemoteSource;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.sbomer.core.features.sbom.utils.PurlSanitizer;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;

import lombok.extern.slf4j.Slf4j;

/**
 * Implementation of the {@link Adjuster} for the {@link GeneratorType#IMAGE_SYFT} type.
 *
 * @author Marek Goldmann
 * @see SyftImageConfig
 */
@Slf4j
public class SyftImageAdjuster extends AbstractAdjuster {
    /**
     * <p>
     * For non-RPM content, a list of paths within the container image for which when a component is found it will be
     * retained in the generated manifest. In case the found component is not on a path in this list, it will be removed
     * from the manifest.
     * </p>
     * ffi
     *
     * <p>
     * If this is {@code null} or an empty list is provided -- all components will be retained in the manifest.
     * </p>
     */
    List<String> paths;
    /**
     * A flag to determine whether RPM packages should be retained in the generated manifests (value set to
     * {@code true}) or removed (value set to {@code false}).
     */
    boolean includeRpms;

    /**
     * A flag to determine whether components merged from the sources ("lookaside cache") manifest should be retained in
     * the generated manifest even when they fall outside the image {@link SyftImageAdjuster#paths} filter. When
     * {@code false} such components remain subject to the paths filter, matching the pre-SBOMER-583 behaviour.
     *
     * @see SyftImageAdjuster#filterComponents(List, Set)
     */
    boolean retainSources;

    final Path workDir;

    /**
     * Location of sources manifest. Any components or dependencies missing from the container image manifest are merged
     * into the generated manifest.
     */
    final Path sourcesManifestPath;

    /**
     * Location of sources metadata. Lists Golang standard library features used in the container image, to be merged
     * into the generated manifest.
     */
    final Path sourcesMetadataPath;

    /**
     * <p>
     * List of supported property name prefixes.
     * </p>
     *
     * @see SyftImageAdjuster#adjustProperties(List)
     */
    private static final List<String> ALLOWED_PROPERTY_PREFIXES = List.of(
            CONTAINER_PROPERTY_PACKAGE_LANGUAGE_PREFIX,
            CONTAINER_PROPERTY_PACKAGE_TYPE_PREFIX,
            CONTAINER_PROPERTY_LOCATION_PATH_PREFIX,
            CONTAINER_PROPERTY_METADATA_VIRTUALPATH_PREFIX,
            CONTAINER_PROPERTY_IMAGE_LABELS_PREFIX);

    /**
     * Backwards-compatible constructor that retains sources-manifest components regardless of the image
     * {@link SyftImageAdjuster#paths} filter.
     */
    public SyftImageAdjuster(
            Path workDir,
            List<String> paths,
            boolean includeRpms,
            Path sourcesManifestPath,
            Path sourcesMetadataPath) {
        this(workDir, paths, includeRpms, sourcesManifestPath, sourcesMetadataPath, true);
    }

    public SyftImageAdjuster(
            Path workDir,
            List<String> paths,
            boolean includeRpms,
            Path sourcesManifestPath,
            Path sourcesMetadataPath,
            boolean retainSources) {
        this.workDir = workDir;
        this.paths = paths;
        this.includeRpms = includeRpms;
        this.sourcesManifestPath = sourcesManifestPath;
        this.sourcesMetadataPath = sourcesMetadataPath;
        this.retainSources = retainSources;
    }

    /**
     * Checks whether the given path is on or under paths specified by the {@link SyftImageAdjuster#paths} list.
     *
     * @param path the path to check
     * @return {@code true} if the path is on or under the paths specified by the {@link SyftImageAdjuster#paths} list,
     *         {@code false} otherwise
     */
    private boolean isOnPath(String path) {
        // In case we haven't provided paths to filter, add all found artifacts.
        if (paths == null || paths.isEmpty()) {
            return true;
        }

        return paths.stream().anyMatch(path::startsWith);
    }

    @Override
    public Bom adjust(Bom bom) {
        log.debug(
                "Starting adjustment of the manifest, parameters: configuration paths: [{}], includeRpms: [{}], sources manifest: {}, sources metadata: {}",
                paths,
                includeRpms,
                sourcesManifestPath != null ? sourcesManifestPath.toAbsolutePath() : null,
                sourcesMetadataPath != null ? sourcesMetadataPath.toAbsolutePath() : null);

        // Purls of components contributed by the sources ("lookaside cache") manifest, captured before the merge
        // so filterComponents can tell them apart from components scanned out of the container image (SBOMER-583).
        Set<String> sourcesPurls = new HashSet<>();

        // Add missing components and dependencies from sources manifest
        adjustEmptyComponents(bom);
        adjustEmptyDependencies(bom);
        if (sourcesManifestPath != null) {
            log.debug(
                    "Adding any missing component or dependency to the main manifest, from sources manifest {}",
                    sourcesManifestPath.toAbsolutePath());
            Bom sourcesBom = SbomUtils.fromPath(sourcesManifestPath);

            if (sourcesBom != null) {
                collectPurls(sourcesBom.getComponents(), sourcesPurls);
                SbomUtils.addMissingComponentsAndDependencies(bom, sourcesBom);
            }
        } else {
            log.warn(
                    "Sources manifest is empty, there are no components nor dependencies to add to the main manifest...");
        }
        if (sourcesMetadataPath != null) {
            log.debug(
                    "Adding any Golang standard library feature components to the main manifest, from sources metadata {}",
                    sourcesMetadataPath.toAbsolutePath());
            Component standardLibraryComponent = SbomUtils.findGolangStandardLibraryComponent(bom);
            if (standardLibraryComponent != null) {
                Set<RemoteSource.Dependency> cachitoDependencies = SbomUtils
                        .readCachitoDependencies(sourcesMetadataPath);
                SbomUtils.addGolangStandardLibraryFeatures(bom, standardLibraryComponent, cachitoDependencies);
            } else {
                log.warn(
                        "Golang standard library component is not present, there are no Golang standard library feature components to add to the main manifest...");
            }
        } else {
            log.warn(
                    "Sources metadata is empty, there are no Golang standard library feature components to add to the main manifest...");
        }

        // Remove components from manifest according to 'paths' and 'includeRpms' parameters
        log.debug("Filtering out all components that do not meet requirements...");

        filterComponents(bom.getComponents(), sourcesPurls);
        adjustProperties(bom);
        adjustNameAndPurl(bom);

        cleanupComponents(bom);

        adjustMainComponent(bom);

        // Populate the dependencies section with components
        adjustDependencies(bom);

        // Adjust the publisher name
        adjustPublisher(bom);
        // Adjust the metadata supplier
        addMissingMetadataSupplier(bom);

        // Add container image hashes to "hashes" object (SBOMER-354)
        addMissingContainerHash(bom);
        return bom;
    }

    /**
     * If the bom components are null, initialize an empty list
     *
     * @param bom the bom to adjust
     */
    private void adjustEmptyComponents(Bom bom) {
        if (bom.getComponents() == null) {
            bom.setComponents(new ArrayList<>());
        }
    }

    /**
     * If the bom dependencies are null, initialize an empty list
     *
     * @param bom the bom to adjust
     */
    private void adjustEmptyDependencies(Bom bom) {
        if (bom.getDependencies() == null) {
            bom.setDependencies(new ArrayList<>());
        }
    }

    /**
     * Removes all components from the component tree that do not meet requirements: as defined by
     * {@link SyftImageAdjuster#includeRpms} and {@link SyftImageAdjuster#paths}.
     *
     * @param components the components to filter
     * @param sourcesPurls purls of components contributed by the sources ("lookaside cache") manifest
     * @see SyftImageAdjuster#includeRpms
     * @see SyftImageAdjuster#paths
     */
    private void filterComponents(List<Component> components, Set<String> sourcesPurls) {
        if (components == null) {
            return;
        }

        components.removeIf(c -> {
            if (c.getPurl() == null) {
                log.debug(
                        "Component (of type '{}', cpe: '{}') does not have purl assigned, marked for removal",
                        c.getType(),
                        c.getCpe());
                return true;
            }

            if (!SbomUtils.hasValidOrSanitizablePurl(c)) {
                log.debug("Component has a purl ({}) which cannot be made valid!", c.getPurl());
                return true;
            }

            // Handle RPMs
            try {
                PackageURL purl = new PackageURL(c.getPurl());
                log.debug("Handling component '{}'", purl);
                if (PackageURL.StandardTypes.RPM.equals(purl.getType())) {
                    // Remove all components that are RPMs if the includeRpms is not set to true
                    log.debug("Component is of type RPM, to be removed: '{}' (includeRpms: {})", purl, includeRpms);
                    return !includeRpms;
                }
            } catch (MalformedPackageURLException e) {
                log.warn("Could not parse the PURL: '{}'", c.getPurl(), e);
            }

            // Handle everything else

            // If paths are not specified, include everything
            if (paths == null || paths.isEmpty()) {
                log.debug("No paths provided, component won't be removed");
                return false;
            }

            Optional<String> location = c.getProperties()
                    .stream()
                    .filter(p -> "syft:location:0:path".equals(p.getName()))
                    .map(Property::getValue)
                    .findFirst();

            // Components contributed by the sources ("lookaside cache") manifest are fetched from the build's
            // remote sources, not scanned from the container image filesystem, and denote their origin via a
            // source-relative syft:location path (e.g. "app/ui/ui-docs/package-lock.json"). The 'paths' filter
            // only describes absolute locations within the image, so when retention is enabled it must not cull
            // these merged dependencies (e.g. dompurify, axios) of any ecosystem. Requiring both a match in the
            // sources manifest and a source-relative location ensures a same-purl component scanned from the image
            // filesystem (an absolute location) stays subject to the filter. Gated by the syft-sources-retention
            // feature flag. (SBOMER-583)
            boolean fromSources = sourcesPurls.contains(c.getPurl());
            boolean sourceRelative = location.isPresent() && !location.get().startsWith("/");
            if (retainSources && fromSources && sourceRelative) {
                log.debug(
                        "Component '{}' originates from the sources manifest ({}), not subject to the image path filter",
                        c.getPurl(),
                        location.get());
                return false;
            }

            // Remove all components that are not on the paths we are interested in
            boolean onPath = location.isEmpty() || !isOnPath(location.get());

            log.debug("Component on path: {}", onPath);

            return onPath;
        });

        // Go deep
        components.forEach(c -> filterComponents(c.getComponents(), sourcesPurls));
    }

    /**
     * Collects the purls of the given components (recursively) into the provided set.
     *
     * @param components the components to collect purls from
     * @param purls the set to populate
     */
    private void collectPurls(List<Component> components, Set<String> purls) {
        if (components == null) {
            return;
        }

        components.forEach(c -> {
            if (c.getPurl() != null) {
                purls.add(c.getPurl());
            }
            collectPurls(c.getComponents(), purls);
        });
    }

    /**
     * <p>
     * Adjust properties in the manifest. This includes a few steps.
     * </p>
     *
     * <p>
     * If there are any properties in the metadata section, move these to the main component's properties.
     * </p>
     *
     * <p>
     * Adjusts any properties in the main component as well as for each component found in the component list
     * (recursively). See {@link SyftImageAdjuster#adjustProperties(List)}.
     * </p>
     *
     * @param bom The manifest to adjust the properties of.
     * @see SyftImageAdjuster#adjustProperties(List)
     */
    private void adjustProperties(Bom bom) {
        log.info("Adjusting manifest properties...");

        Component mainComponent = bom.getMetadata().getComponent();

        // Initialize properties for the main component, if not done so yet
        if (mainComponent.getProperties() == null) {
            mainComponent.setProperties(new ArrayList<>());
        }

        // If there are properties in the metadata field of the manifest, move these into the main component's
        // properties.
        if (bom.getMetadata().getProperties() != null) {
            log.debug(
                    "Moving '{}' properties from metadata to main component",
                    bom.getMetadata().getProperties().size());

            mainComponent.getProperties().addAll(bom.getMetadata().getProperties());
            bom.getMetadata().setProperties(null);
        }

        // Adjust main component's properties...
        adjustProperties(bom.getMetadata().getComponent().getProperties());
        // ...and any other properties found in the component tree.
        bom.getComponents().forEach(c -> adjustProperties(c.getProperties()));

        log.info("Properties adjusted!");
    }

    /**
     * <p>
     * Adjusts the publisher name for Red Hat components.
     * </p>
     *
     * <p>
     * If the publisher is set to "Red Hat, Inc.", update it to "Red Hat" for consistency
     * </p>
     *
     * <p>
     * Adjusts any values in the main component as well as for each component found in the component list (recursively).
     * </p>
     *
     * @param bom The manifest to adjust the properties of.
     */
    private void adjustPublisher(Bom bom) {
        log.info("Adjusting manifest publisher...");

        if (bom == null) {
            return;
        }

        // Adjust the publisher for the main component
        Component mainComponent = bom.getMetadata() != null ? bom.getMetadata().getComponent() : null;
        adjustComponentPublisher(mainComponent);

        // Adjust the publisher for all components in the BOM
        if (bom.getComponents() != null) {
            bom.getComponents().forEach(this::adjustComponentPublisher);
        }
    }

    private void adjustComponentPublisher(Component component) {
        if (component == null) {
            return;
        }

        String currentPublisher = component.getPublisher();
        if ("Red Hat, Inc.".equals(currentPublisher)) {
            component.setPublisher(Constants.PUBLISHER);
        }
    }

    /**
     * Based on the metadata we got the output of Skopeo ({@code skopeo.json} file), adjust main component's purl and
     * name.
     *
     * @param bom the manifest to adjust
     */
    private void adjustNameAndPurl(Bom bom) {
        final Component mainComponent = bom.getMetadata().getComponent();
        ContainerImageInspectOutput inspectData;

        try {
            inspectData = ObjectMapperProvider.json()
                    .readValue(workDir.resolve("skopeo.json").toFile(), ContainerImageInspectOutput.class);

        } catch (IOException e) {
            throw new ApplicationException("Could not read 'skopeo inspect' output", e);
        }

        // 7.4.17
        Optional<Property> versionOpt = SbomUtils
                .findPropertyWithNameInComponent(CONTAINER_PROPERTY_IMAGE_LABEL_VERSION, mainComponent);

        if (versionOpt.isEmpty()) {
            throw new ApplicationException(
                    "The 'version' label was not found within the container image, cannot proceed");
        }

        // 5.1717585311
        Optional<Property> releaseOpt = SbomUtils
                .findPropertyWithNameInComponent(CONTAINER_PROPERTY_IMAGE_LABEL_RELEASE, mainComponent);

        if (releaseOpt.isEmpty()) {
            throw new ApplicationException(
                    "The 'release' label was not found within the container image, cannot proceed");
        }

        String name = inspectData.labels
                .getOrDefault("name", mainComponent.getName().substring(mainComponent.getName().indexOf("/") + 1));
        mainComponent.setName(name);

        try {
            PackageURL purl = PackageURLBuilder.aPackageURL()
                    .withType("oci")
                    .withName(name.substring(name.lastIndexOf("/") + 1))
                    .withVersion(inspectData.getDigest())
                    .withQualifier("os", inspectData.getOs())
                    .withQualifier("arch", inspectData.getArchitecture())
                    .withQualifier("tag", versionOpt.get().getValue() + "-" + releaseOpt.get().getValue())
                    .build();
            log.debug("Generated purl: '{}'", purl);
            mainComponent.setPurl(purl);
        } catch (MalformedPackageURLException e) {
            throw new ApplicationException("Cannot generate purl for container image", e);
        }

    }

    /**
     * <p>
     * Populates the {@link Bom#getDependencies()} with the information we about components have.
     * </p>
     *
     * <p>
     * A main element will be added representing the container image itself with a {@code dependsOn} array populated
     * with the list of all components found in the image.
     * </p>
     *
     * <p>
     * Each component is added to the dependencies section as well with {@code dependsOn} being an empty array.
     * </p>
     *
     * @param bom the manifest to adjust the dependencies of
     */
    private void adjustDependencies(Bom bom) {
        List<Dependency> dependencies = new ArrayList<>();

        populateDependencies(dependencies, bom.getComponents());

        // The image itself is the first element
        Dependency productDependency = dependencies.get(0);

        // If there are more dependencies (besides the main image), add all of them
        // as a product dependency
        if (dependencies.size() > 1) {
            for (Component component : bom.getComponents().subList(1, dependencies.size())) {
                productDependency.addDependency(SbomUtils.createDependency(component.getBomRef()));
            }
        }

        bom.setDependencies(dependencies);
    }

    /**
     * <p>
     * Adds a new {@link Dependency} to a list for each {@link Component} in the list.
     * </p>
     *
     * <p>
     * CAse where a component has nested components is handled as well.
     * </p>
     */
    private void populateDependencies(List<Dependency> dependencies, List<Component> components) {
        if (components == null) {
            return;
        }

        components.forEach(component -> {
            // Check that there isn't already a dependency with the bom-ref equals to the new purl, otherwise do not
            // update it
            if (!dependencies.stream().map(Dependency::getRef).toList().contains(component.getPurl())) {
                component.setBomRef(component.getPurl());
            }
            dependencies.add(SbomUtils.createDependency(component.getBomRef()));
            populateDependencies(dependencies, component.getComponents());
        });

    }

    /**
     * <p>
     * Updates property names to our rules.
     * </p>
     *
     * <p>
     * Removes any properties which names do not start with allowed prefixes,
     * {@link SyftImageAdjuster#ALLOWED_PROPERTY_PREFIXES}.
     * </p>
     *
     * @param properties the properties to adjust
     * @see SyftImageAdjuster#ALLOWED_PROPERTY_PREFIXES
     */
    private void adjustProperties(List<Property> properties) {
        if (properties == null) {
            return;
        }

        // Adjust property names
        properties.forEach(p -> {
            String newName = p.getName()
                    .replace(CONTAINER_PROPERTY_SYFT_PREFIX, CONTAINER_PROPERTY_SYFT_REPLACEMENT_PREFIX);

            // log.debug("Adjusting property name from '{}' to '{}'", p.getName(), newName);

            p.setName(newName);
        });

        // Remove properties we don't care about
        properties.removeIf(prop -> {
            boolean supportedProp = ALLOWED_PROPERTY_PREFIXES.stream()
                    .anyMatch(prefix -> prop.getName().startsWith(prefix));

            // if (!supportedProp) {
            // log.debug(
            // "Property '{}' with value '{}' is not on the supported properties list, removing...",
            // prop.getName(),
            // prop.getValue());
            // }

            return !supportedProp;
        });

        properties.stream()
                .filter(
                        property -> (CONTAINER_PROPERTY_IMAGE_LABEL_VENDOR).equals(property.getName())
                                || (CONTAINER_PROPERTY_IMAGE_LABEL_MANTAINER).equals(property.getName()))
                .forEach(property -> {
                    if ("Red Hat, Inc.".equals(property.getValue())) {
                        property.setValue(Constants.SUPPLIER_NAME);
                    }
                });

    }

    @Override
    protected void cleanupComponent(Component component) {
        // log.debug("Cleaning up component '{}'", component.getPurl());

        // Remove CPE, we don't use it now
        component.setCpe(null);

        if (component.getProperties() != null) {
            // Adjust purl for Java components
            Property propType = SbomUtils
                    .findPropertyWithNameInComponent(CONTAINER_PROPERTY_PACKAGE_TYPE_PREFIX, component)
                    .orElse(null);

            if (component.getPurl() != null && propType != null) {
                switch (propType.getValue()) {
                    case "java-archive":
                        // log.debug(
                        // "Adjusting purl for the '{}' Java component by adding '?type=jar' suffix...",
                        // component.getPurl());
                        component.setPurl(component.getPurl() + "?type=jar");
                        break;

                    case "rpm":
                        // log.debug(
                        // "Adjusting purl for the '{}' RPM component by removing all qualifiers besides 'arch' and
                        // 'epoch'...",
                        // component.getPurl());

                        cleanupPurl(component);
                        break;

                    default:
                        break;
                }
            }
        }

        cleanupExternalReferences(component.getExternalReferences());
        log.debug("Component '{}' adjusted", component.getPurl());
    }

    private void cleanupPurl(Component component) {
        try {
            String cleanedUpPurl = doCleanupPurl(component.getPurl());
            component.setPurl(cleanedUpPurl);
        } catch (MalformedPackageURLException e) {
            String sanitizedPurl = PurlSanitizer.sanitizePurl(component.getPurl());
            log.debug("Sanitized purl {} to {}, cleaning up one more time", component.getPurl(), sanitizedPurl);
            component.setPurl(sanitizedPurl);

            try {
                String cleanedUpPurl = doCleanupPurl(component.getPurl());
                component.setPurl(cleanedUpPurl);
            } catch (MalformedPackageURLException e1) {
                log.warn("Could not clean up purl '{}'", component.getPurl(), e);
            }
        }
    }

    private String doCleanupPurl(String purl) throws MalformedPackageURLException {
        PackageURL packageURL = new PackageURL(purl);

        Map<String, String> origQualifiers = packageURL.getQualifiers();
        if (origQualifiers == null) {
            return packageURL.toString();
        }

        TreeMap<String, String> qualifiers = new TreeMap<>(origQualifiers);

        // If we removed any qualifiers, we need to rebuild the purl
        if (qualifiers.entrySet().removeIf(q -> !q.getKey().equals("arch") && !q.getKey().equals("epoch"))) {

            return new PackageURL(
                    packageURL.getType(),
                    packageURL.getNamespace(),
                    packageURL.getName(),
                    packageURL.getVersion(),
                    qualifiers,
                    packageURL.getSubpath()).toString();
        }
        return packageURL.toString();
    }

}
