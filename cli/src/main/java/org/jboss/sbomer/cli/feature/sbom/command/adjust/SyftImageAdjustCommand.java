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
package org.jboss.sbomer.cli.feature.sbom.command.adjust;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.cyclonedx.model.Bom;
import org.jboss.sbomer.cli.feature.sbom.adjuster.SyftImageAdjuster;
import org.jboss.sbomer.cli.feature.sbom.command.PathConverter;

import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(
        mixinStandardHelpOptions = true,
        name = "syft-image",
        description = "Adjust the Syft manifest output for a container image")
@Slf4j
public class SyftImageAdjustCommand extends AbstractAdjustCommand {

    @Option(names = "--path-filter")
    List<String> paths = new ArrayList<>();

    @Option(names = "--rpms", defaultValue = "false", negatable = true)
    boolean rpms;

    @Option(
            names = "--retain-sources",
            arity = "1",
            defaultValue = "false",
            description = "Retain components merged from the sources manifest even when they fall outside --path-filter")
    boolean retainSources;

    @Option(
            names = { "--sources-manifest" },
            paramLabel = "FILE",
            description = "Location of the sources manifest",
            converter = PathConverter.class)
    Path sourcesManifestPath;

    @Option(
            names = { "--sources-metadata" },
            paramLabel = "FILE",
            description = "Location of the sources metadata",
            converter = PathConverter.class)
    Path sourcesMetadataPath;

    @Override
    protected String getAdjusterType() {
        return "syft-image";
    }

    @Override
    protected Bom doAdjust(Bom bom, Path workDir) {
        log.debug("Paths: {}", paths);
        log.debug("RPMs: {}", rpms);
        log.debug("Retain sources: {}", retainSources);
        log.debug("Sources manifest: {}", sourcesManifestPath != null ? sourcesManifestPath.toAbsolutePath() : null);
        log.debug("Sources metadata: {}", sourcesMetadataPath != null ? sourcesMetadataPath.toAbsolutePath() : null);

        SyftImageAdjuster adjuster = new SyftImageAdjuster(
                workDir,
                paths,
                rpms,
                sourcesManifestPath,
                sourcesMetadataPath,
                retainSources);

        return adjuster.adjust(bom);
    }
}
