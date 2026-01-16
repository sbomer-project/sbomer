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
package org.jboss.sbomer.service.generator.image.controller;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.config.SyftImageConfig;
import org.jboss.sbomer.core.features.sbom.enums.GenerationRequestType;
import org.jboss.sbomer.core.features.sbom.utils.MDCUtils;
import org.jboss.sbomer.service.feature.FeatureFlags;
import org.jboss.sbomer.service.feature.sbom.k8s.model.GenerationRequest;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationPhase;
import org.jboss.sbomer.service.feature.sbom.k8s.resources.Labels;

import io.fabric8.kubernetes.api.model.Duration;
import io.fabric8.kubernetes.api.model.OwnerReferenceBuilder;
import io.fabric8.kubernetes.api.model.PersistentVolumeClaimVolumeSourceBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.tekton.v1beta1.ParamBuilder;
import io.fabric8.tekton.v1beta1.ParamValue;
import io.fabric8.tekton.v1beta1.TaskRefBuilder;
import io.fabric8.tekton.v1beta1.TaskRun;
import io.fabric8.tekton.v1beta1.TaskRunBuilder;
import io.fabric8.tekton.v1beta1.WorkspaceBindingBuilder;
import io.javaoperatorsdk.operator.api.reconciler.Context;
import io.javaoperatorsdk.operator.processing.dependent.kubernetes.CRUDNoGCKubernetesDependentResource;
import io.javaoperatorsdk.operator.processing.dependent.kubernetes.KubernetesDependent;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;

@KubernetesDependent
@Slf4j
public class TaskRunSyftImageGenerateDependentResource
        extends CRUDNoGCKubernetesDependentResource<TaskRun, GenerationRequest> {

    public static final String PARAM_COMMAND_CONTAINER_IMAGE = "image";
    public static final String PARAM_PATHS = "paths";
    public static final String PARAM_RPMS = "rpms";
    public static final String PARAM_PROCESSORS = "processors";
    public static final String TASK_SUFFIX = "-generate-image-syft";
    public static final String SA_SUFFIX = "-sa";

    @ConfigProperty(name = "SBOMER_RELEASE", defaultValue = "sbomer")
    protected String release;

    @Inject
    KubernetesClient client;

    @Inject
    protected FeatureFlags featureFlags;

    TaskRunSyftImageGenerateDependentResource() {
        super(TaskRun.class);
    }

    public TaskRunSyftImageGenerateDependentResource(Class<TaskRun> resourceType) {
        super(resourceType);
    }

    @Override
    protected TaskRun desired(GenerationRequest generationRequest, Context<GenerationRequest> context) {

        MDCUtils.removeOtelContext();
        MDCUtils.addOtelContext(generationRequest.getMDCOtel());

        log.debug(
                "Preparing dependent resource for the '{}' phase related to '{}' GenerationRequest",
                SbomGenerationPhase.GENERATE,
                generationRequest.getMetadata().getName());
        Map<String, String> labels = Labels.defaultLabelsToMap(GenerationRequestType.CONTAINERIMAGE);

        labels.put(Labels.LABEL_PHASE, SbomGenerationPhase.GENERATE.name().toLowerCase());
        labels.put(Labels.LABEL_GENERATION_REQUEST_ID, generationRequest.getId());
        labels.put(Labels.LABEL_OTEL_TRACE_ID, generationRequest.getTraceId());
        labels.put(Labels.LABEL_OTEL_SPAN_ID, generationRequest.getSpanId());
        labels.put(Labels.LABEL_OTEL_TRACEPARENT, generationRequest.getTraceParent());

        Duration timeout;

        try {
            timeout = Duration.parse("6h");
        } catch (ParseException e) {
            throw new ApplicationException("Cannot set timeout", e);
        }

        String rpmsParam = Boolean.toString(generationRequest.getConfig(SyftImageConfig.class).isIncludeRpms());

        // Determine paths based on feature flag and config
        List<String> paths = generationRequest.getConfig(SyftImageConfig.class).getPaths();
        if (featureFlags.syftManifestOptEnabled()) {
            // When feature flag is enabled, append "/opt" to the paths
            List<String> effectivePaths = new ArrayList<>();
            if (paths != null && !paths.isEmpty()) {
                effectivePaths.addAll(paths);
            }
            if (!effectivePaths.contains("/opt")) {
                effectivePaths.add("/opt");
            }
            paths = effectivePaths;
            log.debug("Syft manifest optimization enabled, using paths: {}", paths);
        } else if (paths == null) {
            paths = Collections.emptyList();
        }

        // TODO: Disabled for now
        // TektonResourceUtils.adjustComputeResources(taskRun);

        return new TaskRunBuilder().withNewMetadata()
                .withNamespace(generationRequest.getMetadata().getNamespace())
                .withLabels(labels)
                .withName(generationRequest.dependentResourceName(SbomGenerationPhase.GENERATE))
                .withOwnerReferences(
                        new OwnerReferenceBuilder().withKind(generationRequest.getKind())
                                .withName(generationRequest.getMetadata().getName())
                                .withApiVersion(generationRequest.getApiVersion())
                                .withUid(generationRequest.getMetadata().getUid())
                                .build())
                .endMetadata()
                .withNewSpec()
                .withServiceAccountName(release + SA_SUFFIX)
                .withTimeout(timeout)
                .withParams(
                        new ParamBuilder().withName(PARAM_COMMAND_CONTAINER_IMAGE)
                                .withNewValue(generationRequest.getIdentifier())
                                .build(),
                        new ParamBuilder().withName(PARAM_PROCESSORS)
                                .withNewValue(generationRequest.getConfig().toProcessorsCommand())
                                .build(),
                        new ParamBuilder().withName(PARAM_PATHS).withValue(new ParamValue(paths)).build(),
                        new ParamBuilder().withName(PARAM_RPMS).withValue(new ParamValue(rpmsParam)).build())
                .withTaskRef(new TaskRefBuilder().withName(release + TASK_SUFFIX).build())

                .withWorkspaces(
                        new WorkspaceBindingBuilder().withSubPath(generationRequest.getMetadata().getName())
                                .withName("data")
                                .withPersistentVolumeClaim(
                                        new PersistentVolumeClaimVolumeSourceBuilder().withClaimName(release + "-sboms")
                                                .build())
                                .build())
                .endSpec()
                .build();
    }
}
