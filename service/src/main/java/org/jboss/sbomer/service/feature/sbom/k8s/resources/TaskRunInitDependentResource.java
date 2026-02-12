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
package org.jboss.sbomer.service.feature.sbom.k8s.resources;

import java.util.Map;
import java.util.Objects;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.sbomer.core.features.sbom.enums.GenerationRequestType;
import org.jboss.sbomer.core.features.sbom.utils.MDCUtils;
import org.jboss.sbomer.service.feature.sbom.k8s.model.GenerationRequest;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationPhase;

import io.fabric8.kubernetes.api.model.OwnerReferenceBuilder;
import io.fabric8.kubernetes.api.model.PersistentVolumeClaimVolumeSourceBuilder;
import io.fabric8.tekton.v1beta1.ParamBuilder;
import io.fabric8.tekton.v1beta1.TaskRefBuilder;
import io.fabric8.tekton.v1beta1.TaskRun;
import io.fabric8.tekton.v1beta1.TaskRunBuilder;
import io.fabric8.tekton.v1beta1.WorkspaceBindingBuilder;
import io.javaoperatorsdk.operator.api.reconciler.Context;
import io.javaoperatorsdk.operator.processing.dependent.kubernetes.CRUDNoGCKubernetesDependentResource;
import io.javaoperatorsdk.operator.processing.dependent.kubernetes.KubernetesDependent;
import lombok.extern.slf4j.Slf4j;

@KubernetesDependent
@Slf4j
public class TaskRunInitDependentResource extends CRUDNoGCKubernetesDependentResource<TaskRun, GenerationRequest> {

    public static final String RESULT_NAME = "config";
    public static final String PARAM_BUILD_ID_NAME = "build-id";
    public static final String PARAM_CONFIG_NAME = "config";
    public static final String PARAM_FEATURE_GENERIC_PURL_VERSION_REGEX = "generic-purl-version-regex-enabled";
    public static final String TASK_SUFFIX = "-init";
    public static final String SA_SUFFIX = "-sa";

    @ConfigProperty(name = "SBOMER_RELEASE", defaultValue = "sbomer")
    String release;

    TaskRunInitDependentResource() {
        super(TaskRun.class);
    }

    public TaskRunInitDependentResource(Class<TaskRun> resourceType) {
        super(resourceType);
    }

    /**
     * <p>
     * Method that creates a {@link TaskRun} related to the {@link GenerationRequest} in order to perform the
     * initialization.
     * </p>
     *
     * <p>
     * This is done just one right after the {@link GenerationRequest} is created within the system.
     * </p>
     */
    @Override
    protected TaskRun desired(GenerationRequest generationRequest, Context<GenerationRequest> context) {

        MDCUtils.removeOtelContext();
        MDCUtils.addOtelContext(generationRequest.getMDCOtel());

        log.debug(
                "Preparing dependent resource for the '{}' phase related to '{}'",
                SbomGenerationPhase.INIT,
                generationRequest.getMetadata().getName());

        Map<String, String> labels = Labels.defaultLabelsToMap(GenerationRequestType.BUILD);

        labels.put(Labels.LABEL_IDENTIFIER, generationRequest.getIdentifier());
        labels.put(Labels.LABEL_PHASE, SbomGenerationPhase.INIT.name().toLowerCase());
        labels.put(Labels.LABEL_GENERATION_REQUEST_ID, generationRequest.getId());
        labels.put(Labels.LABEL_OTEL_TRACE_ID, generationRequest.getTraceId());
        labels.put(Labels.LABEL_OTEL_SPAN_ID, generationRequest.getSpanId());
        labels.put(Labels.LABEL_OTEL_TRACEPARENT, generationRequest.getTraceParent());

        return new TaskRunBuilder().withNewMetadata()
                .withNamespace(generationRequest.getMetadata().getNamespace())
                .withLabels(labels)
                .withName(generationRequest.dependentResourceName(SbomGenerationPhase.INIT))
                .withOwnerReferences(
                        new OwnerReferenceBuilder().withKind(generationRequest.getKind())
                                .withName(generationRequest.getMetadata().getName())
                                .withApiVersion(generationRequest.getApiVersion())
                                .withUid(generationRequest.getMetadata().getUid())
                                .build())
                .endMetadata()
                .withNewSpec()
                .withServiceAccountName(release + SA_SUFFIX)
                .withParams(
                        new ParamBuilder().withName(PARAM_BUILD_ID_NAME)
                                .withNewValue(generationRequest.getIdentifier())
                                .build(),
                        new ParamBuilder().withName(PARAM_CONFIG_NAME)
                                .withNewValue(Objects.requireNonNullElse(generationRequest.getJsonConfig(), ""))
                                .build())
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
