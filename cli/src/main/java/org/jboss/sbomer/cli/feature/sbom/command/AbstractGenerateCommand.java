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
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicLong;

import org.eclipse.jgit.api.CloneCommand;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.api.errors.InvalidRemoteException;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.jboss.pnc.dto.Build;
import org.jboss.sbomer.cli.errors.GitCloneException;
import org.jboss.sbomer.cli.errors.pnc.InvalidPncBuildStateException;
import org.jboss.sbomer.cli.errors.pnc.MissingPncBuildException;
import org.jboss.sbomer.cli.errors.pnc.UnsupportedPncBuildException;
import org.jboss.sbomer.cli.feature.sbom.client.facade.SBOMerClientFacade;
import org.jboss.sbomer.cli.feature.sbom.command.mixin.GeneratorToolMixin;
import org.jboss.sbomer.cli.feature.sbom.git.GitCredentialsProvider;
import org.jboss.sbomer.cli.feature.sbom.model.Sbom;
import org.jboss.sbomer.cli.feature.sbom.model.SbomGenerationRequest;
import org.jboss.sbomer.cli.feature.sbom.utils.otel.OtelCLIUtils;
import org.jboss.sbomer.core.config.DefaultGenerationConfig.DefaultGeneratorConfig;
import org.jboss.sbomer.core.config.SbomerConfigProvider;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.config.PncBuildConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.ProductConfig;
import org.jboss.sbomer.core.features.sbom.enums.GeneratorType;
import org.jboss.sbomer.core.features.sbom.utils.FileUtils;
import org.jboss.sbomer.core.features.sbom.utils.MDCUtils;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.sbomer.core.features.sbom.utils.OtelHelper;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.core.features.sbom.utils.commandline.CommandLineParserUtil;
import org.jboss.sbomer.core.pnc.PncService;

import com.fasterxml.jackson.databind.JsonNode;

import jakarta.inject.Inject;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.ParentCommand;

@Slf4j
public abstract class AbstractGenerateCommand implements Callable<Integer> {
    @Mixin
    GeneratorToolMixin generator;

    @Getter
    @ParentCommand
    GenerateCommand parent;

    @Inject
    protected PncService pncService;

    @Inject
    protected SBOMerClientFacade sbomerClientFacade;

    @Inject
    protected GitCredentialsProvider gitCredentialsProvider;

    protected final SbomerConfigProvider sbomerConfigProvider = SbomerConfigProvider.getInstance();

    /**
     * <p>
     * Implementation of the SBOM generation for the project located in the {@code parent.getOutput()} directory.
     * </p>
     *
     * @return a {@link Path} to the generated BOM file.
     */
    protected abstract Path doGenerate(String buildCmdOptions);

    protected abstract GeneratorType generatorType();

    protected String generatorArgs() {
        DefaultGeneratorConfig defaultGeneratorConfig = sbomerConfigProvider.getDefaultGenerationConfig()
                .forGenerator(generatorType());

        if (generator.getArgs() == null) {
            String defaultArgs = defaultGeneratorConfig.defaultArgs();
            log.debug("Using default arguments for the {} execution: {}", generatorType(), defaultArgs);

            return defaultArgs;
        } else {
            log.debug("Using provided arguments for the {} execution: {}", generatorType(), generator.getArgs());

            return generator.getArgs();
        }
    }

    protected String toolVersion() {
        DefaultGeneratorConfig defaultGeneratorConfig = sbomerConfigProvider.getDefaultGenerationConfig()
                .forGenerator(generatorType());

        if (generator.getVersion() == null) {
            String toolVersion = defaultGeneratorConfig.defaultVersion();
            log.debug("Using default tool version for the {} generator: {}", generatorType(), toolVersion);

            return toolVersion;
        } else {
            log.debug("Using provided version for the {} generator: {}", generatorType(), generator.getVersion());

            return generator.getVersion();
        }
    }

    @Override
    public Integer call() {
        try {
            // Make sure there is no context
            MDCUtils.removeContext();
            MDCUtils.addIdentifierContext(parent.getBuildId());
            MDCUtils.addOtelContext(OtelCLIUtils.getOtelContextFromEnvVariables());

            Map<String, String> attributes = Map.of(
                    "params.generator.type",
                    generatorType().toString(),
                    "params.generator.args",
                    generatorArgs(),
                    "params.tool.version",
                    toolVersion(),
                    "params.identifier",
                    parent.getBuildId(),
                    "params.destination",
                    parent.getOutput().toFile().getAbsolutePath());

            OtelCLIUtils.startOtel(
                    OtelCLIUtils.SBOMER_CLI_NAME,
                    OtelHelper.getEffectiveClassName(this.getClass()) + ".generate",
                    attributes);

            // Fetch build information
            Build build = pncService.getBuild(parent.getBuildId());

            if (build == null) {
                throw new MissingPncBuildException("Could not fetch the PNC build with id '{}'", parent.getBuildId());
            }

            // Filter only valid PNC builds
            if (!isValidBuild(build)) {
                throw new InvalidPncBuildStateException(
                        "Build '{}' is not valid! Build cannot be temporary and progress needs to be 'FINISHED' with status 'SUCCESS' or 'NO_REBUILD_REQUIRED'. Currently: temporary: {}, progress: '{}', status: '{}'",
                        parent.getBuildId(),
                        build.getTemporaryBuild(),
                        build.getProgress(),
                        build.getStatus());
            }

            // Filter only valid PNC build types
            if (!isValidBuildType(build)) {
                throw new UnsupportedPncBuildException(
                        "The generation of SBOMs for the build type '{}' is not yet implemented!",
                        build.getBuildConfigRevision().getBuildType());
            }

            // Get the correct scm information for builds which have either SUCCESS or NO_REBUILD_REQUIRED status
            String scmUrl = build.getScmUrl();
            String scmTag = build.getScmTag();

            JsonNode bom = null;

            if (org.jboss.pnc.enums.BuildStatus.NO_REBUILD_REQUIRED.equals(build.getStatus())) {
                // The source code details are inside the noRebuildCause build
                scmUrl = build.getNoRebuildCause().getScmUrl();
                scmTag = build.getNoRebuildCause().getScmTag();

                // Let's see if there noRebuildCause build has been already generated.

                // Find the last successful SbomGenerationRequest for this build
                SbomGenerationRequest sbomRequest = sbomerClientFacade
                        .searchLastSuccessfulGeneration(build.getNoRebuildCause().getId());
                if (sbomRequest != null) {
                    try {
                        // The workdir name has the format "product-{index}". Extract the index
                        String numericPart = parent.getWorkdir()
                                .toAbsolutePath()
                                .toString()
                                .replaceAll(".*/[^-]*-(\\d+)$", "$1"); // NOSONAR We control the path, it's safe
                        int productIndex = Integer.parseInt(numericPart);

                        // Get the runtime configuration related to the ProductConfig with the current index being
                        // processed
                        // here
                        List<ProductConfig> productConfigs = ((PncBuildConfig) sbomRequest.getConfig()).getProducts();
                        if (productConfigs != null && productIndex >= 0 && productIndex < productConfigs.size()) {

                            // Let's verify that the configuration provided to the generator is the same, otherwise do
                            // the
                            // generation again
                            ProductConfig productConfig = productConfigs.get(productIndex);

                            String toolVersion = toolVersion();
                            String generatorArgs = generatorArgs();
                            GeneratorType type = generatorType();

                            log.debug(
                                    "Comparing current toolVersion: '{}', generatorArgs: '{}', generatorType: '{}' with the values retrieved from the past generation in DB: toolVersion: '{}', generatorArgs: '{}', generatorType: '{}'...",
                                    toolVersion,
                                    generatorArgs,
                                    type,
                                    productConfig.getGenerator().getVersion(),
                                    productConfig.getGenerator().getArgs(),
                                    productConfig.getGenerator().getType());

                            if (Objects.equals(productConfig.getGenerator().getVersion(), toolVersion())
                                    && Objects.equals(productConfig.getGenerator().getArgs(), generatorArgs())
                                    && Objects.equals(productConfig.getGenerator().getType(), generatorType())) {

                                // Find the corresponding SBOM generated from the request for the product index
                                Sbom sbom = sbomerClientFacade.searchSbomsOfRequest(sbomRequest.getId(), productIndex);
                                if (sbom != null) {
                                    bom = sbom.getSbom();
                                    log.info(
                                            "Found compatible generated SBOM with id: '{}' from generation request: '{}', from previous build '{}'. Reusing it!",
                                            sbom.getId(),
                                            sbomRequest.getId(),
                                            sbom.getIdentifier());
                                }
                            }
                        } else {
                            log.warn(
                                    "Could not find the runtime product config related to index '{}', will regenerate the SBOM...",
                                    productIndex);
                        }
                    } catch (NumberFormatException ex) {
                        log.warn(
                                "Could not find extract product index from workDir path '{}', will regenerate the SBOM...",
                                parent.getWorkdir().toAbsolutePath());
                    }

                } else {
                    log.warn(
                            "Could not find existing successful SBOM Generation Requests for PNC build '{}', will regenerate the SBOM...",
                            build.getNoRebuildCause().getId());
                }
            }

            Path sbomPath = null;
            boolean isForce = parent.isForce();

            if (bom != null) {
                // I have retrieved an SBOM generated previously with the same configuration, I can reuse it!
                sbomPath = parent.getWorkdir().resolve("_bom.json");
                try {
                    if (!Files.exists(sbomPath)) {
                        Files.createDirectories(parent.getWorkdir());
                        Files.createFile(sbomPath);
                        // At this point I have created the file and dir, so in case I have an error while saving the
                        // file
                        // content below, I can tell the doClone to clean everything up
                        isForce = true;
                    }
                    // Remove the Errata properties so that they can be changed if needed (override is not possible)
                    bom = SbomUtils.removeErrataProperties(bom);

                    // Write the JsonNode to the source file
                    ObjectMapperProvider.json().writeValue(sbomPath.toFile(), bom);
                } catch (IOException e) {
                    sbomPath = null;
                    log.warn("Could not copy reused bom, will regenerate the SBOM...", e);
                }
            }

            if (sbomPath == null) {

                try {
                    // Clone the source code related to the build
                    doClone(scmUrl, scmTag, parent.getWorkdir(), isForce);
                } catch (ApplicationException e) {
                    throw new GitCloneException("Unable to clone repository '{}'", scmUrl, e);
                }

                // In case the original build command script contains profiles, projects list or system properties
                // definitions, get them as a best effort and pass them to the SBOM generation to try to resolve the
                // same
                // dependency tree.
                String buildCmdOptions = CommandLineParserUtil.getLaunderedCommandScript(build);
                log.info("buildCmdOptions: '{}'", buildCmdOptions);

                // Generate the SBOM
                sbomPath = doGenerate(buildCmdOptions);
            }

            try {
                Files.copy(sbomPath, parent.getOutput(), StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                throw new ApplicationException(
                        "Could not move the generated SBOM from '{}' to target location: '{}'",
                        sbomPath,
                        parent.getOutput().toAbsolutePath(),
                        e);
            }

            log.info("Generation finished, SBOM available at: '{}'", parent.getOutput().toFile().getAbsolutePath());
            return 0;
        } finally {
            MDCUtils.removeContext();
            OtelCLIUtils.stopOTel();
        }
    }

    protected void doClone(String url, String tag, Path path, boolean force) {
        log.info("Cloning '{}' repository and '{}' tag into '{}'...", url, tag, path.toAbsolutePath());

        if (Files.exists(path)) {
            if (!force) {
                throw new ApplicationException("Path '{}' already exists and force is disabled", path);
            }

            log.warn("Cleaning up the '{}' output directory before cloning...", path);

            // Delete the output directory
            FileUtils.rmdir(path);

            log.debug("Done.");
        }

        try {
            Files.createDirectories(path);
        } catch (IOException e) {
            log.error("Could not create the '{}' directory", path, e);
        }

        log.info("Cloning the repository to {}...", path);

        // Build clone command
        CloneCommand cloneCommand = Git.cloneRepository()
                .setDirectory(path.toFile())
                .setURI(url)
                .setBranch(tag)
                .setDepth(1); // Shallow clone for efficiency

        // Add credentials if available
        CredentialsProvider credentials = gitCredentialsProvider.getCredentials(url);
        if (credentials != null) {
            log.debug("Using authenticated clone for: {}", url);
            cloneCommand.setCredentialsProvider(credentials);
        } else {
            log.debug("Using public clone (no authentication) for: {}", url);
        }

        try (Git ignored = cloneCommand.call()) {
            log.info("Successfully cloned the repository to {}", path);
        } catch (InvalidRemoteException e) {
            throw new ApplicationException(
                    "Unknown error occurred while preparing to clone the '{}'  repository",
                    url,
                    e);
        } catch (GitAPIException e) {
            log.error("Unable to clone the '{}' repository", url, e);

            // Provide helpful error message for authentication failures
            if (e.getMessage().contains("not authorized") || e.getMessage().contains("authentication failed")
                    || e.getMessage().contains("Authentication is required")) {
                throw new ApplicationException(
                        "Authentication failed for repository '{}'. "
                                + "Please configure Git token in application.yaml or via environment variables.",
                        url,
                        e);
            }

            throw new ApplicationException("Unable to clone the repository", e);
        }

        log.info("Done, source code available in the '{}' directory", path);

        // Please note that this ignores the block size of a particular storage,
        // and because of this, the number can be different compared to when
        // a utility like `du` is being used to determine the size.
        log.info("Directory size: {} MB", String.format("%.02f", (float) dirSize(path) / 1024));
    }

    /**
     * Calculates directory size for a given path.
     *
     * @param path the path to the directory
     * @return Size in kB.
     */
    protected long dirSize(Path path) {
        final AtomicLong size = new AtomicLong(0);

        try {
            Files.walkFileTree(path, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    size.addAndGet(attrs.size());
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            throw new AssertionError("An error occurred while calculating size of the directory");
        }

        return size.get() / 1024;
    }

    private boolean isValidBuild(Build build) {
        return !build.getTemporaryBuild() && org.jboss.pnc.enums.BuildProgress.FINISHED.equals(build.getProgress())
                && (org.jboss.pnc.enums.BuildStatus.SUCCESS.equals(build.getStatus())
                        || org.jboss.pnc.enums.BuildStatus.NO_REBUILD_REQUIRED.equals(build.getStatus()));
    }

    private boolean isValidBuildType(Build build) {
        return org.jboss.pnc.enums.BuildType.MVN.equals(build.getBuildConfigRevision().getBuildType())
                || org.jboss.pnc.enums.BuildType.MVN_RPM.equals(build.getBuildConfigRevision().getBuildType())
                || org.jboss.pnc.enums.BuildType.GRADLE.equals(build.getBuildConfigRevision().getBuildType())
                || org.jboss.pnc.enums.BuildType.NPM.equals(build.getBuildConfigRevision().getBuildType())
                || org.jboss.pnc.enums.BuildType.SBT.equals(build.getBuildConfigRevision().getBuildType());
    }
}
