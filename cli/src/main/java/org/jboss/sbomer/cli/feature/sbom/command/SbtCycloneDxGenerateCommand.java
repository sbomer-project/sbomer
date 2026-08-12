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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Metadata;
import org.jboss.pnc.dto.Artifact;
import org.jboss.pnc.dto.Build;
import org.jboss.sbomer.cli.feature.sbom.generate.ProcessRunner;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.Constants;
import org.jboss.sbomer.core.features.sbom.enums.GeneratorType;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;

import com.github.packageurl.PackageURL.StandardTypes;

import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine.Command;

@Slf4j
@Command(
        mixinStandardHelpOptions = true,
        name = "sbt-cyclonedx-plugin",
        aliases = { "sbt-cyclonedx" },
        description = "SBOM generation for SBT projects using the CycloneDX Sbt plugin",
        subcommands = { ProcessCommand.class })
public class SbtCycloneDxGenerateCommand extends AbstractSbtGenerateCommand {

    private final Pattern VERSION_PATTERN = Pattern.compile("set\s+version\s*:=\s*\"([^\"]+)\"");
    private final Pattern NAME_PATTERN = Pattern.compile("set\s+name\s*:=\s*\"([^\"]+)\"");
    private final String BOM_REF_REGEXP_TEMPLATE = "^(pkg:%s/%s/%s[^@]*)@(%s)$";

    @Override
    protected Path doGenerate(String buildCmdOptions) {
        log.info("Starting SBOM generation using the CycloneDX Sbt plugin...");

        // 1. Create the destination folder in case it does not exist
        List<String> createDir = List.of("mkdir", "-p", "project");
        ProcessRunner.run(parent.getWorkdir(), createDir.toArray(new String[0]));

        // 2. Add the SBT plugin to the configuration
        String[] addPlugin = { "bash", "-c", "echo 'addSbtPlugin(\"com.github.sbt\" % \"sbt-sbom\" % \"" + toolVersion()
                + "\")' >> project/plugins.sbt" };
        ProcessRunner.run(parent.getWorkdir(), addPlugin);

        // 3. Trigger the proper manifest generation using the SBT plugin
        ProcessRunner.run(parent.getWorkdir(), command(buildCmdOptions));

        try {
            // Retrieve all the manifests generated
            List<Path> paths = findManifests(parent.getWorkdir());

            if (paths.size() == 0) {
                throw new ApplicationException(
                        "Unable to find the generated SBOM under the '{}' directory",
                        parent.getWorkdir().toAbsolutePath());
            }

            // The build command contains the final name and version assigned to the build
            String componentFullName = extractNameFromSBTCommand(buildCmdOptions);
            String componentVersion = extractVersionFromSBTCommand(buildCmdOptions);
            log.info("Root component fullName: {}; version: {}", componentFullName, componentVersion);

            Path rootManifestPath = findRootComponentManifest(paths, componentFullName, componentVersion);
            log.info("Found rootManifestPath: {}; ", rootManifestPath.toAbsolutePath().toString());

            mergeRootWithAllManifests(rootManifestPath, paths);
            addMissingData(rootManifestPath, componentFullName, componentVersion);

            return rootManifestPath;
        } catch (IOException e) {
            throw new ApplicationException(
                    "Unable to find the generated SBOM under the '{}' directory",
                    parent.getWorkdir().toAbsolutePath());
        }
    }

    private Path findRootComponentManifest(List<Path> paths, String componentFullName, String componentVersion) {
        if (paths.size() == 1) {
            return paths.get(0);
        }

        if (componentFullName == null || componentVersion == null) {
            // If there are no name and version set, find the closest manifest to the root of the project
            return paths.stream()
                    .min(
                            (p1, p2) -> Integer.compare(
                                    parent.getWorkdir().relativize(p1).getNameCount(),
                                    parent.getWorkdir().relativize(p2).getNameCount()))
                    .orElse(paths.get(0));
        }

        // The name and version are set and the SBT has generated a manifest with a corresponding name
        String rootManifestName = String.format("%s-%s.bom.json", componentFullName, componentVersion);
        log.info("Looking for root manifest with name: {}", rootManifestName);
        return paths.stream()
                .filter(path -> path.getFileName().toString().equals(rootManifestName))
                .findFirst()
                .orElse(paths.get(0));
    }

    private void mergeRootWithAllManifests(Path rootManifestPath, List<Path> manifestsPaths) {
        Bom rootBom = SbomUtils.fromPath(rootManifestPath);

        Set<String> existingDependencyRefs = rootBom.getDependencies()
                .stream()
                .map(Dependency::getRef)
                .collect(Collectors.toSet());

        Set<String> existingComponentsPurls = Stream.ofNullable(rootBom.getComponents())
                .flatMap(Collection::stream)
                .map(Component::getPurl)
                .collect(Collectors.toSet());

        manifestsPaths.stream()
                .filter(path -> !path.equals(rootManifestPath))
                .map(SbomUtils::fromPath)
                .forEach(componentBom -> {
                    Stream.ofNullable(componentBom.getComponents())
                            .flatMap(Collection::stream)
                            .filter(comp -> existingComponentsPurls.add(comp.getPurl()))
                            .forEach(rootBom::addComponent);

                    Stream.ofNullable(componentBom.getDependencies())
                            .flatMap(Collection::stream)
                            .filter(dep -> existingDependencyRefs.add(dep.getRef()))
                            .forEach(rootBom.getDependencies()::add);
                });

        // Write the manifest back to file
        SbomUtils.toPath(rootBom, rootManifestPath);
    }

    /**
     * Updates the bom-ref in the dependency hierarchy, looking for nested dependencies and provides.
     *
     * @param bom the bom to update
     * @param regExp the regExp that matches the bom-ref to update
     * @param newRef the new reference
     */
    private void updateMatchingBomRefs(Bom bom, String regExp, String newRef) {
        Pattern pattern = Pattern.compile(regExp);
        // Recursively update the dependencies in the BOM
        if (bom.getDependencies() != null) {
            List<Dependency> updatedDependencies = new ArrayList<>(bom.getDependencies().size());
            for (Dependency dependency : bom.getDependencies()) {
                Dependency updatedDependency = SbomUtils.updateDependencyRef(dependency, pattern, newRef);
                updatedDependencies.add(updatedDependency);
            }
            bom.setDependencies(updatedDependencies);
        }
    }

    private void addMissingData(Path rootManifestPath, String componentFullName, String componentVersion) {
        Bom rootBom = SbomUtils.fromPath(rootManifestPath);
        addMissingMetadataComponent(rootBom, componentFullName, componentVersion);
        addMissingQualifiersAndHashes(rootBom);
        SbomUtils.toPath(rootBom, rootManifestPath);
    }

    private void addMissingMetadataComponent(Bom rootBom, String componentFullName, String componentVersion) {
        Metadata metadata = rootBom.getMetadata();
        if (metadata == null) {
            metadata = new Metadata();
            metadata.setTimestamp(Date.from(Instant.now()));
        }
        if (metadata.getComponent() == null) {
            if (componentFullName != null && componentVersion != null) {
                String[] componentGA = componentFullName.split(Constants.SBT_COMPONENT_COORDINATES_SEPARATOR);
                String componentGroup = componentGA[0].replace(Constants.SBT_COMPONENT_DOT_SEPARATOR, ".");
                String componentName = componentGA[1];
                String purl = String.format(
                        "pkg:%s/%s/%s@%s",
                        StandardTypes.MAVEN,
                        componentGroup,
                        componentName,
                        componentVersion);

                Component metadataComponent = SbomUtils.createComponent(
                        componentGroup,
                        componentName,
                        componentVersion,
                        null,
                        purl,
                        Component.Type.LIBRARY);
                SbomUtils.setPublisher(metadataComponent);
                SbomUtils.setSupplier(metadataComponent);

                // Fetch build information
                Build build = pncService.getBuild(parent.getBuildId());
                SbomUtils.setPncBuildMetadata(metadataComponent, build, pncService.getApiUrl());

                metadata.setComponent(metadataComponent);

                // The SBT Plugin creates the main bom-ref from the component group, name and version, but not quite, so
                // we need a regExp
                String bomRefRegExp = String.format(
                        BOM_REF_REGEXP_TEMPLATE,
                        StandardTypes.MAVEN,
                        componentGroup.replace(".", "\\."),
                        componentFullName,
                        componentVersion);
                updateMatchingBomRefs(rootBom, bomRefRegExp, purl);
            }
        } else {
            // Fallback: use the first component from the bom if available
            List<Component> components = rootBom.getComponents();
            if (SbomUtils.isNotEmpty(components)) {
                metadata.setComponent(components.get(0));
            }
        }

        rootBom.setMetadata(metadata);
    }

    private void addMissingQualifiersAndHashes(Bom rootBom) {
        // The SBT plugin does not put the jar qualifier in purls, let's add it
        String newPurl = SbomUtils
                .addQualifiersToPurlOfComponent(rootBom.getMetadata().getComponent(), Map.of("type", "jar"));
        rootBom.getMetadata().getComponent().setPurl(newPurl);
        Stream.ofNullable(rootBom.getComponents()).flatMap(Collection::stream).forEach(c -> {
            String updatedPurl = SbomUtils.addQualifiersToPurlOfComponent(c, Map.of("type", "jar"));
            c.setPurl(updatedPurl);
        });

        // Let's verify all the components have hashes added
        if (rootBom.getMetadata().getComponent().getHashes() == null
                || rootBom.getMetadata().getComponent().getHashes().isEmpty()) {
            Artifact artifact = pncService.getArtifact(
                    rootBom.getMetadata().getComponent().getPurl(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty());
            if (artifact != null) {
                // Make sure the component has hashes
                SbomUtils.addHashIfMissing(rootBom.getMetadata().getComponent(), artifact.getMd5(), Hash.Algorithm.MD5);
                SbomUtils.addHashIfMissing(
                        rootBom.getMetadata().getComponent(),
                        artifact.getSha1(),
                        Hash.Algorithm.SHA1);
                SbomUtils.addHashIfMissing(
                        rootBom.getMetadata().getComponent(),
                        artifact.getSha256(),
                        Hash.Algorithm.SHA_256);
            }
        }
        Stream.ofNullable(rootBom.getComponents()).flatMap(Collection::stream).forEach(c -> {
            if (c.getHashes() == null || c.getHashes().isEmpty()) {
                Artifact artifact = pncService
                        .getArtifact(c.getPurl(), Optional.empty(), Optional.empty(), Optional.empty());
                if (artifact != null) {
                    // Make sure the component has hashes
                    SbomUtils.addHashIfMissing(c, artifact.getMd5(), Hash.Algorithm.MD5);
                    SbomUtils.addHashIfMissing(c, artifact.getSha1(), Hash.Algorithm.SHA1);
                    SbomUtils.addHashIfMissing(c, artifact.getSha256(), Hash.Algorithm.SHA_256);
                }
            }
        });
    }

    /**
     * Traverses through the directory tree and finds all manifests (files that ends with {@code bom.json}) and returns
     * all found files as a {@link List} of {@link Path}s.
     *
     * @param directory The top-level directory where search for manifests should be started.
     * @return List of {@link Path}s to found manifests.
     */
    private List<Path> findManifests(Path directory) throws IOException {
        // Check if directory exists and is a directory
        if (Files.notExists(directory) || !Files.isDirectory(directory)) {
            throw new IllegalArgumentException(
                    "The provided path is not a valid directory: " + directory.toAbsolutePath());
        }

        log.info("Finding manifests under the '{}' directory...", directory.toAbsolutePath());

        try (Stream<Path> paths = Files.walk(directory)) {
            List<Path> manifestPaths = paths.filter(path -> path.getFileName().toString().endsWith("bom.json"))
                    .filter(Files::isRegularFile)
                    .sorted()
                    .peek(path -> log.info("Found manifest at path '{}'", path.toAbsolutePath())) // NOSONAR: peek() is
                                                                                                  // used just for
                                                                                                  // logging
                    .toList();

            log.info("Found {} generated manifests", manifestPaths.size());
            return manifestPaths;
        }
    }

    private String[] command(String buildCmdOptions) {
        String genArgs = generatorArgs();
        List<String> cmd = List.of("sbt", buildCmdOptions + genArgs, "makeBom");
        log.debug("Executing command: '{}'", "sbt " + buildCmdOptions + genArgs + " makeBom");
        return cmd.toArray(new String[0]);
    }

    private String extractNameFromSBTCommand(String sbtCommand) {
        Matcher nameMatcher = NAME_PATTERN.matcher(sbtCommand);
        return nameMatcher.find() ? nameMatcher.group(1) : null;
    }

    private String extractVersionFromSBTCommand(String sbtCommand) {
        Matcher versionMatcher = VERSION_PATTERN.matcher(sbtCommand);
        return versionMatcher.find() ? versionMatcher.group(1) : null;
    }

    @Override
    protected GeneratorType generatorType() {
        return GeneratorType.SBT_CYCLONEDX;
    }

}
