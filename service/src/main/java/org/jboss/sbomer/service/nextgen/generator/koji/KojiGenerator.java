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
package org.jboss.sbomer.service.nextgen.generator.koji;

import java.io.IOException;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.eclipse.microprofile.context.ManagedExecutor;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.utils.FileUtils;
import org.jboss.sbomer.core.features.sbom.utils.MDCUtils;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.sbomer.service.feature.sbom.config.GenerationRequestControllerConfig;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationPhase;
import org.jboss.sbomer.service.leader.LeaderManager;
import org.jboss.sbomer.service.nextgen.controller.tekton.AbstractTektonController;
import org.jboss.sbomer.service.nextgen.controller.tekton.TektonUtilities;
import org.jboss.sbomer.service.nextgen.core.dto.api.GenerationRequest;
import org.jboss.sbomer.service.nextgen.core.dto.model.GenerationRecord;
import org.jboss.sbomer.service.nextgen.core.dto.model.ManifestRecord;
import org.jboss.sbomer.service.nextgen.core.enums.GenerationResult;
import org.jboss.sbomer.service.nextgen.core.enums.GenerationStatus;
import org.jboss.sbomer.service.nextgen.core.rest.SBOMerClient;
import org.jboss.sbomer.service.nextgen.core.utils.JacksonUtils;
import org.jboss.sbomer.service.nextgen.service.EntityMapper;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;

import io.fabric8.kubernetes.api.model.Duration;
import io.fabric8.kubernetes.api.model.PersistentVolumeClaimVolumeSourceBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientException;
import io.fabric8.tekton.v1beta1.Param;
import io.fabric8.tekton.v1beta1.ParamBuilder;
import io.fabric8.tekton.v1beta1.TaskRefBuilder;
import io.fabric8.tekton.v1beta1.TaskRun;
import io.fabric8.tekton.v1beta1.TaskRunBuilder;
import io.fabric8.tekton.v1beta1.WorkspaceBindingBuilder;
import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.validation.ValidationException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@ApplicationScoped
public class KojiGenerator extends AbstractTektonController {

    public static final String PARAM_BREW_BUILD_ID = "build-id";
    public static final String PARAM_CBOM = "cbom";
    public static final String PARAM_CBOM_TIMEOUT = "cbom-timeout";

    public static final String TASK_SUFFIX = "-generator-brew-rpm";

    public static final String GENERATOR_NAME = "koji";
    public static final String GENERATOR_VERSION = "0.1.0";

    private KojiGenerator() {
        super(null, null, null, null, null, null);
    }

    @Inject
    public KojiGenerator(
            @RestClient SBOMerClient sbomerClient,
            KubernetesClient kubernetesClient,
            GenerationRequestControllerConfig controllerConfig,
            ManagedExecutor managedExecutor,
            EntityMapper mapper,
            LeaderManager leaderManager) {
        super(sbomerClient, kubernetesClient, controllerConfig, managedExecutor, mapper, leaderManager);
    }

    @Override
    public Set<String> getSupportedTypes() {
        return Set.of("BREW_RPM");
    }

    @Override
    public String getGeneratorName() {
        return GENERATOR_NAME;
    }

    @Override
    public String getGeneratorVersion() {
        return GENERATOR_VERSION;
    }

    @Override
    public void generate(GenerationRecord generationRecord) {
        log.info("Preparing Tekton Task Run for generation '{}'", generationRecord.id());

        TaskRun desired = desired(generationRecord);

        log.trace("Prepared TaskRun for generation '{}': {}", generationRecord.id(), desired);

        try {
            kubernetesClient.resources(TaskRun.class).resource(desired).create();
        } catch (KubernetesClientException e) {
            log.warn("Unable to schedule Tekton TaskRun", e);

            updateStatus(
                    generationRecord.id(),
                    GenerationStatus.FAILED,
                    GenerationResult.ERR_SYSTEM,
                    "Unable to schedule Tekton TaskRun: {}",
                    e.getMessage());

            return;
        }
    }

    @Scheduled(
            every = "20s",
            delay = 10,
            delayUnit = TimeUnit.SECONDS,
            concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    @Override
    protected void ensureInformer() {
        super.ensureInformer();
    }

    @Override
    protected void reconcileGenerating(GenerationRecord generation, Set<TaskRun> relatedTaskRuns) {
        log.debug("Reconcile '{}' for Generation '{}'...", GenerationStatus.GENERATING, generation.id());

        boolean inProgress = false;
        boolean success = true;
        TaskRun erroredTaskRun = null;

        for (TaskRun tr : relatedTaskRuns) {

            if (!isFinished(tr)) {
                inProgress = true;
                break;
            }

            if (!Boolean.TRUE.equals(isSuccessful(tr))) {
                erroredTaskRun = tr;
                inProgress = false;
                success = false;
                break;
            }
        }

        // Still in progress
        if (inProgress) {
            log.info("Generation '{}' is still in progress", generation.id());
            return;
        }

        if (!success) {
            Map<String, String> erroredAnnotations = erroredTaskRun.getMetadata().getAnnotations();
            GenerationResult result = isOomKilled(erroredTaskRun) ? GenerationResult.ERR_OOM
                    : GenerationResult.ERR_GENERAL;
            int retryCount = Integer.parseInt(erroredAnnotations.getOrDefault(ANNOTATION_RETRY_COUNT, "0"));
            GenerationRequest request = JacksonUtils.parse(GenerationRequest.class, generation.request());
            KojiBrewRpmOptions options = retrieveOptions(request);
            int maxCount = options.retries().maxCount();

            if (result == GenerationResult.ERR_GENERAL || ++retryCount > maxCount) {
                String detailedFailureMessage = getDetailedFailureMessage(erroredTaskRun);
                updateStatus(
                        generation.id(),
                        GenerationStatus.FAILED,
                        result,
                        "Generation failed, the TaskRun returned failure: {}",
                        detailedFailureMessage);
            } else {
                log.info("Retrying Tekton Task Run for generation '{}', count '{}'", generation.id(), retryCount);
                double memoryMultiplier = options.retries().memoryMultiplier();
                TaskRun taskRun = createRetry(erroredTaskRun, retryCount, memoryMultiplier);

                try {
                    // Prevent last task run continuously being rescheduled
                    kubernetesClient.resources(TaskRun.class).resource(erroredTaskRun).delete();
                    kubernetesClient.resources(TaskRun.class).resource(taskRun).create();
                } catch (KubernetesClientException e) {
                    log.warn("Unable to schedule Tekton TaskRun retry", e);

                    updateStatus(
                            generation.id(),
                            GenerationStatus.FAILED,
                            GenerationResult.ERR_SYSTEM,
                            "Unable to schedule Tekton TaskRun retry: {}",
                            e.getMessage());
                }
            }

            return;
        }

        // Construct the path to the working directory of the generator
        Path generationDir = Path.of(controllerConfig.sbomDir(), generation.id());

        log.debug("Reading manifests from '{}'...", generationDir.toAbsolutePath());

        List<Path> manifestPaths;

        try {
            manifestPaths = FileUtils.findManifests(generationDir);
        } catch (IOException e) {
            log.error("Unexpected IO exception occurred while trying to find generated manifests", e);

            updateStatus(
                    generation.id(),
                    GenerationStatus.FAILED,
                    GenerationResult.ERR_SYSTEM,
                    "Generation succeeded, but reading generated SBOMs failed due IO exception. See logs for more information.");

            return;
        }

        if (manifestPaths.isEmpty()) {
            log.error("No manifests found, this is unexpected");

            updateStatus(
                    generation.id(),
                    GenerationStatus.FAILED,
                    GenerationResult.ERR_SYSTEM,
                    "Generation succeed, but no manifests could be found. At least one was expected. See logs for more information.");
            return;
        }

        // Read manifests
        List<JsonNode> boms;

        try {
            boms = JacksonUtils.readBoms(manifestPaths);
        } catch (Exception e) {
            log.error("Unable to read one or more manifests", e);

            updateStatus(
                    generation.id(),
                    GenerationStatus.FAILED,
                    GenerationResult.ERR_SYSTEM,
                    "Generation succeeded, but reading generated manifests failed was not successful. See logs for more information.");

            return;
        }

        // TODO: Validate manifests

        // Store manifests
        List<ManifestRecord> manifests;

        try {
            manifests = storeBoms(generation, boms);
        } catch (ValidationException e) {
            // There was an error when validating the entity, most probably the SBOM is not valid
            log.error("Unable to validate generated SBOMs: {}", e.getMessage(), e);

            updateStatus(
                    generation.id(),
                    GenerationStatus.FAILED,
                    GenerationResult.ERR_SYSTEM,
                    "Generation failed. One or more generated SBOMs failed validation: {}. See logs for more information.",
                    e.getMessage());

            return;
        }

        try {
            // syftImageController.performPost(sboms); // TODO: add this back
        } catch (ApplicationException e) {
            updateStatus(generation.id(), GenerationStatus.FAILED, GenerationResult.ERR_POST, e.getMessage());
            return;
        }

        updateStatus(
                generation.id(),
                GenerationStatus.FINISHED,
                GenerationResult.SUCCESS,
                "Generation finished successfully");
    }

    @Override
    public TaskRun desired(GenerationRecord generation) {

        MDCUtils.removeOtelContext();

        log.debug(
                "Preparing dependent resource for the '{}' phase related to Generation with id '{}'",
                SbomGenerationPhase.GENERATE,
                generation.id());

        // TODO: populate traces when we create generations
        Map<String, String> labels = TektonUtilities.createBasicGenerationLabels(generation, getGeneratorName());

        GenerationRequest request = JacksonUtils.parse(GenerationRequest.class, generation.request());
        KojiBrewRpmOptions options = retrieveOptions(request);

        Duration timeout;

        try {
            timeout = Duration.parse("6h");
        } catch (ParseException e) {
            throw new ApplicationException("Cannot set timeout", e);
        }

        String taskSuffix = null;
        List<Param> params = new ArrayList<>();

        // Select Tekton Task and set parameters depending on the type of the target
        switch (request.target().type()) {
            case "BREW_RPM":
                taskSuffix = TASK_SUFFIX;

                params.add(
                        new ParamBuilder().withName(PARAM_BREW_BUILD_ID)
                                .withNewValue(request.target().identifier())
                                .build());

                // Add CBOM parameters if specified
                if (options.cbom() != null) {
                    params.add(
                            new ParamBuilder().withName(PARAM_CBOM)
                                    .withNewValue(String.valueOf(options.cbom()))
                                    .build());
                }

                if (options.cbomTimeout() != null && !options.cbomTimeout().isEmpty()) {
                    params.add(
                            new ParamBuilder().withName(PARAM_CBOM_TIMEOUT)
                                    .withNewValue(options.cbomTimeout())
                                    .build());
                }
                break;

            default:
                break;
        }

        if (taskSuffix == null) {
            throw new ApplicationException("Unknown target type: {}", request.target().type());
        }

        TaskRun taskRun = new TaskRunBuilder().withNewMetadata()
                .withLabels(labels)
                // TODO: this should be a method
                .withName(
                        "generation-" + generation.id().toLowerCase() + "-" + SbomGenerationPhase.GENERATE.ordinal()
                                + "-" + SbomGenerationPhase.GENERATE.name().toLowerCase())
                .addToAnnotations(ANNOTATION_RETRY_COUNT, "0")
                .endMetadata()
                .withNewSpec()
                .withServiceAccountName(release + SA_SUFFIX)
                .withTimeout(timeout)
                .withParams(params)
                .withTaskRef(new TaskRefBuilder().withName(release + taskSuffix).build())
                .withStepOverrides(TektonUtilities.resourceOverrides(request))
                .withWorkspaces(
                        new WorkspaceBindingBuilder().withSubPath(generation.id())
                                .withName("data")
                                .withPersistentVolumeClaim(
                                        new PersistentVolumeClaimVolumeSourceBuilder().withClaimName(release + "-sboms")
                                                .build())
                                .build())
                .endSpec()
                .build();

        configureOwner(taskRun);

        return taskRun;
    }

    private KojiBrewRpmOptions retrieveOptions(GenerationRequest request) {
        JsonNode jsonNode = request.generator().config().options();
        try {
            return ObjectMapperProvider.json().treeToValue(jsonNode, KojiBrewRpmOptions.class);
        } catch (JsonProcessingException e) {
            throw new ApplicationException(
                    "Unexpected options provided, expected Syft generator options, but got: {}",
                    jsonNode,
                    e);
        }
    }

}
