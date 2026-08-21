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
package org.jboss.sbomer.test.e2e.rw;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import org.hamcrest.CoreMatchers;
import org.jboss.sbomer.test.e2e.E2EStageBase;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Tag("stage")
@Execution(ExecutionMode.CONCURRENT)
class StageGenerationRequestIT extends E2EStageBase {

    static Path sbomPath(String fileName) {
        return Paths.get("src", "test", "resources", "requests", fileName);
    }

    private static final String MAVEN_BUILD_ID = "BD44LZFQA5YAA";
    private static final String GRADLE_5_BUILD_ID = "BD2NA27VAVIAA";
    private static final String GRADLE_4_BUILD_ID = "BDW7L6D3DUQAA";
    private static final String NODEJS_NPM_BUILD_ID = "BCT4ZINAVZYAA";

    @Test
    @Execution(ExecutionMode.CONCURRENT)
    void testSuccessfulGenerationMavenBuild() throws IOException {
        String requestBody = Files.readString(sbomPath("pnc-build-" + MAVEN_BUILD_ID + ".json"));
        String requestId = requestGeneration(requestBody);
        waitForRequest(requestId);
        List<String> generationIds = generationIdsFromRequest(requestId);
        assertEquals(1, generationIds.size());
        String generationId = generationIds.get(0);
        log.info("Maven build - Generation Request created: {}", generationId);

        log.info("Maven build finished, waiting for UMB message");

        publishedUmbMessage(
                generationId,
                message -> message.body("headers.generation_request_id", CoreMatchers.is(generationId))
                        .body("headers.pnc_build_id", CoreMatchers.is(MAVEN_BUILD_ID))
                        .body("msg.build.id", CoreMatchers.is(MAVEN_BUILD_ID))
                        .body("msg.sbom.generationRequest.id", CoreMatchers.is(generationId)));

        log.info("Maven build passed");
    }

    @Test
    @Execution(ExecutionMode.CONCURRENT)
    void testSuccessfulGenerationGradle5Build() throws IOException {
        String requestBody = Files.readString(sbomPath("pnc-build-" + GRADLE_5_BUILD_ID + ".json"));
        String requestId = requestGeneration(requestBody);
        waitForRequest(requestId);
        List<String> generationIds = generationIdsFromRequest(requestId);
        assertEquals(1, generationIds.size());
        String generationId = generationIds.get(0);

        log.info("Gradle 5 build - Generation Request created: {}", generationId);

        // log.info("Gradle 5 build finished, waiting for UMB message");

        // publishedUmbMessage(generationId, message -> {
        // message.body("headers.generation_request_id", CoreMatchers.is(generationId))
        // .body("headers.pnc_build_id", CoreMatchers.is(GRADLE_5_BUILD_ID))
        // .body("msg.build.id", CoreMatchers.is(GRADLE_5_BUILD_ID))
        // .body("msg.sbom.generationRequest.id", CoreMatchers.is(generationId));
        // });

        log.info("Gradle 5 build passed");
    }

    @Test
    @Disabled("Temporarily disabled due to upstream service issue with Gradle 4 build BDW7L6D3DUQAA")
    @Execution(ExecutionMode.CONCURRENT)
    void testSuccessfulGenerationGradle4Build() throws IOException {
        String requestBody = Files.readString(sbomPath("pnc-build-" + GRADLE_4_BUILD_ID + ".json"));
        String requestId = requestGeneration(requestBody);
        waitForRequest(requestId);
        List<String> generationIds = generationIdsFromRequest(requestId);
        assertEquals(1, generationIds.size());
        String generationId = generationIds.get(0);

        log.info("Gradle 4 build - Generation Request created: {}", generationId);

        // log.info("Gradle 4 build finished, waiting for UMB message");

        // Awaitility.await().atMost(2, TimeUnit.MINUTES).pollInterval(5, TimeUnit.SECONDS).until(() -> {
        // givenLastCompleteUmbMessageForGeneration(gradle4GenerationRequestId).then()
        // .body("raw_messages[0].headers.generation_request_id", CoreMatchers.is(gradle4GenerationRequestId))
        // .body("raw_messages[0].headers.pnc_build_id", CoreMatchers.is(GRADLE_4_BUILD_ID))
        // .body("raw_messages[0].msg.build.id", CoreMatchers.is(GRADLE_4_BUILD_ID))
        // .body("raw_messages[0].msg.sbom.generationRequest.id", CoreMatchers.is(gradle4GenerationRequestId));

        // return true;
        // });

        log.info("Gradle 4 build passed");
    }

    @Test
    @Execution(ExecutionMode.CONCURRENT)
    void testSuccessfulGenerationNodeJsNpmBuild() throws IOException {
        String requestBody = Files.readString(sbomPath("pnc-build-" + NODEJS_NPM_BUILD_ID + ".json"));
        String requestId = requestGeneration(requestBody);
        waitForRequest(requestId);
        List<String> generationIds = generationIdsFromRequest(requestId);
        assertEquals(1, generationIds.size());
        String generationId = generationIds.get(0);

        log.info("NodeJs NPM build - Generation Request created: {}", generationId);

        // log.info("Node.js NPM build finished, waiting for UMB message");

        // publishedUmbMessage(generationId, message -> {
        // message.body("headers.generation_request_id", CoreMatchers.is(generationId))
        // .body("headers.pnc_build_id", CoreMatchers.is(NODEJS_NPM_BUILD_ID))
        // .body("msg.build.id", CoreMatchers.is(NODEJS_NPM_BUILD_ID))
        // .body("msg.sbom.generationRequest.id", CoreMatchers.is(generationId));
        // });

        log.info("NodeJs NPM build passed");
    }
}
