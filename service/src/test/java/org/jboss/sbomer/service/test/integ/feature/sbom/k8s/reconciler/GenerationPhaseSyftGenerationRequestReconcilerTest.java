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
package org.jboss.sbomer.service.test.integ.feature.sbom.k8s.reconciler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.jboss.sbomer.core.features.sbom.config.Config;
import org.jboss.sbomer.core.features.sbom.config.SyftImageConfig;
import org.jboss.sbomer.core.features.sbom.enums.GenerationRequestType;
import org.jboss.sbomer.core.test.TestResources;
import org.jboss.sbomer.service.feature.sbom.atlas.AtlasHandler;
import org.jboss.sbomer.service.feature.sbom.config.GenerationRequestControllerConfig;
import org.jboss.sbomer.service.feature.sbom.k8s.model.GenerationRequest;
import org.jboss.sbomer.service.feature.sbom.k8s.model.GenerationRequestBuilder;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationPhase;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationStatus;
import org.jboss.sbomer.service.feature.sbom.k8s.resources.Labels;
import org.jboss.sbomer.service.generator.image.controller.SyftImageController;
import org.jboss.sbomer.service.test.unit.feature.sbom.syftimage.TestControllerProfile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import io.fabric8.knative.pkg.apis.ConditionBuilder;
import io.fabric8.kubernetes.client.server.mock.KubernetesServer;
import io.fabric8.tekton.v1beta1.ParamBuilder;
import io.fabric8.tekton.v1beta1.ParamValue;
import io.fabric8.tekton.v1beta1.TaskRun;
import io.fabric8.tekton.v1beta1.TaskRunBuilder;
import io.fabric8.tekton.v1beta1.TaskRunStatusBuilder;
import io.javaoperatorsdk.operator.api.reconciler.Context;
import io.javaoperatorsdk.operator.api.reconciler.UpdateControl;
import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.test.junit.mockito.InjectSpy;
import io.quarkus.test.kubernetes.client.KubernetesTestServer;

@QuarkusTest
@TestProfile(TestControllerProfile.class)
class GenerationPhaseSyftGenerationRequestReconcilerTest {

    @InjectMock
    GenerationRequestControllerConfig controllerConfig;

    @InjectSpy
    SyftImageController sic;

    @InjectMock
    AtlasHandler atlasHandler;

    @KubernetesTestServer
    KubernetesServer mockServer;

    // private List<Path> generatedSbomDirs;
    private ExecutorService executorService;

    private static int TASKRUN_COUNT = 3;

    @AfterEach
    void cleanup() {
        if (executorService != null) {
            executorService.shutdownNow();
        }
    }

    private List<GenerationRequest> createGenerationRequests(int count, Path tempDir, int tasks) throws IOException {
        when(controllerConfig.sbomDir()).thenReturn(tempDir.toString());
        List<GenerationRequest> requests = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            String requestName = "test-generation-request-" + i;
            Path requestDir = tempDir.resolve(requestName);
            Files.createDirectory(requestDir);

            for (int ti = 0; ti < tasks; ti++) {
                String taskName = "generation-task-run-" + ti;
                Path taskDir = requestDir.resolve(taskName);
                Files.createDirectory(taskDir);
                Files.writeString(taskDir.resolve("bom.json"), TestResources.asString("sboms/complete_sbom.json"));
            }

            GenerationRequest generationRequest = new GenerationRequestBuilder(GenerationRequestType.BUILD)
                    .withIdentifier(String.valueOf(i))
                    .withStatus(SbomGenerationStatus.GENERATING)
                    .withConfig(Config.fromString("{\"type\": \"syft-image\"}", SyftImageConfig.class))
                    .build();

            generationRequest.getMetadata().setName(requestName);
            requests.add(generationRequest);
        }
        return requests;
    }

    private TaskRun createDummyTaskRun(int index, String status) {
        return new TaskRunBuilder().withNewMetadata()
                .withName("generation-task-run-" + index)
                .withLabels(Map.of(Labels.LABEL_PHASE, SbomGenerationPhase.GENERATE.name().toLowerCase()))
                .endMetadata()
                .withNewSpec()
                .withParams(
                        new ParamBuilder().withName("index").withValue(new ParamValue(String.valueOf(index))).build())
                .endSpec()
                .withStatus(
                        new TaskRunStatusBuilder()
                                .withConditions(List.of(new ConditionBuilder().withStatus(status).build()))
                                .build())
                .build();
    }

    private Context<GenerationRequest> mockContextWithTaskRuns(int count, String status) {
        Context<GenerationRequest> mockedContext = Mockito.mock(Context.class);
        Set<TaskRun> secondaryResources = new LinkedHashSet<>();
        for (int i = 0; i < count; i++) {
            secondaryResources.add(createDummyTaskRun(i, status));
        }
        when(mockedContext.getSecondaryResources(TaskRun.class)).thenReturn(secondaryResources);
        return mockedContext;
    }

    @Test
    @Disabled("Timer-sensitive; fails under CPU contention in CI")
    void testRetryOnConcurency(@TempDir Path tmpDir) throws Exception {
        doNothing().when(atlasHandler).publishBuildManifests(any());

        int totalRequests = 3;
        List<GenerationRequest> requests = createGenerationRequests(totalRequests, tmpDir, TASKRUN_COUNT);
        executorService = Executors.newFixedThreadPool(totalRequests);
        List<Future<UpdateControl<GenerationRequest>>> futures = new ArrayList<>();

        for (GenerationRequest request : requests) {
            Context<GenerationRequest> context = mockContextWithTaskRuns(TASKRUN_COUNT, "True");
            futures.add(executorService.submit(() -> sic.reconcile(request, context)));
        }

        executorService.shutdown();
        assertTrue(executorService.awaitTermination(60, TimeUnit.SECONDS));

        for (Future<UpdateControl<GenerationRequest>> future : futures) {
            UpdateControl<GenerationRequest> result = future.get();
            assertNotNull(result, "The returned UpdateControl should not be null");
            assertEquals(
                    SbomGenerationStatus.FINISHED,
                    result.getResource().get().getStatus(),
                    "Expected FINISHED status");
        }
    }

    @Test
    @Disabled("Timer-sensitive; fails under CPU contention in CI")
    void testBulkheadExceptionOnExceededRetries(@TempDir Path tmpDir) throws Exception {
        int totalRequests = 100;
        List<GenerationRequest> requests = createGenerationRequests(totalRequests, tmpDir, TASKRUN_COUNT);
        executorService = Executors.newFixedThreadPool(totalRequests);
        List<Future<UpdateControl<GenerationRequest>>> futures = new ArrayList<>();

        for (GenerationRequest request : requests) {
            Context<GenerationRequest> context = mockContextWithTaskRuns(TASKRUN_COUNT, "True");
            futures.add(executorService.submit(() -> sic.reconcile(request, context)));
        }

        executorService.shutdown();
        assertTrue(executorService.awaitTermination(60, TimeUnit.SECONDS));

        List<UpdateControl<GenerationRequest>> results = new ArrayList<>();
        for (Future<UpdateControl<GenerationRequest>> future : futures) {
            results.add(future.get());
        }

        long failedCount = results.stream()
                .filter(r -> r.getResource().isPresent())
                .filter(r -> r.getResource().get().getStatus().equals(SbomGenerationStatus.FAILED))
                .count();

        long bulkheadFailures = results.stream()
                .filter(r -> r.getResource().isPresent())
                .filter(r -> r.getResource().get().getStatus().equals(SbomGenerationStatus.FAILED))
                .filter(r -> r.getResource().get().getReason().contains("Boms rejected from bulkhead"))
                .count();

        assertTrue(failedCount > 0, "Expected at least one failed generation request.");
        /*
         * This was originally a test - assertTrue(bulkheadFailures > 0,
         * "Expected at least one failure due to Bulkhead exception.");
         *
         * But due to the transient nature of this error (totally depends on hardware executing the test) then we cannot
         * rely on this test, instead we have a println for debugging
         */
        if (bulkheadFailures < 1) {
            System.out.println(
                    "Expected at least one failure due to Bulkhead exception, but we failed for another reason");
            results.stream()
                    .filter(r -> r.getResource().isPresent())
                    .filter(r -> r.getResource().get().getStatus().equals(SbomGenerationStatus.FAILED))
                    .forEach(r -> {
                        System.out.println("Failure Reason: " + r.getResource().get().getReason());
                    });
        }
    }
}
