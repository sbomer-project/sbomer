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
package org.jboss.sbomer.service.feature.sbom.features.generator.rpm.controller;

import java.text.ParseException;
import java.util.Map;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.config.BrewRPMConfig;
import org.jboss.sbomer.core.features.sbom.enums.GenerationRequestType;
import org.jboss.sbomer.core.features.sbom.utils.MDCUtils;
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
public class TaskRunBrewRPMGenerateDependentResource
        extends CRUDNoGCKubernetesDependentResource<TaskRun, GenerationRequest> {

    public static final String ANNOTATION_ADVISORY = "sbomer.jboss.org/errata-advisory";
    public static final String ANNOTATION_PRODUCT_VERSION = "sbomer.jboss.org/errata-product-version";
    public static final String ANNOTATION_ADVISORY_ID = "sbomer.jboss.org/errata-advisory-id";
    public static final String ANNOTATION_PRODUCT_VERSION_ID = "sbomer.jboss.org/errata-product-version-id";
    public static final String ANNOTATION_BUILD_ID = "sbomer.jboss.org/brew-build-id";
    public static final String ANNOTATION_BUILD_NVR = "sbomer.jboss.org/brew-build-nvr";

    public static final String PARAM_BREW_BUILD_ID = "build-id";
    public static final String PARAM_CBOM = "cbom";
    public static final String PARAM_CBOM_TIMEOUT = "cbom-timeout";

    public static final String TASK_SUFFIX = "-generator-brew-rpm";
    public static final String SA_SUFFIX = "-sa";

    @ConfigProperty(name = "SBOMER_RELEASE", defaultValue = "sbomer")
    protected String release;

    @Inject
    KubernetesClient client;

    TaskRunBrewRPMGenerateDependentResource() {
        super(TaskRun.class);
    }

    public TaskRunBrewRPMGenerateDependentResource(Class<TaskRun> resourceType) {
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
        Map<String, String> labels = Labels.defaultLabelsToMap(GenerationRequestType.BREW_RPM);

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

        BrewRPMConfig config = generationRequest.getConfig(BrewRPMConfig.class);
        Map<String, String> annotations = Map.of(
                ANNOTATION_ADVISORY_ID,
                String.valueOf(config.getAdvisoryId()),
                ANNOTATION_ADVISORY,
                config.getAdvisory(),
                ANNOTATION_BUILD_ID,
                String.valueOf(config.getBrewBuildId()),
                ANNOTATION_BUILD_NVR,
                config.getBrewBuildNVR());

        // Build params list
        var params = java.util.List.of(
                new ParamBuilder().withName(PARAM_BREW_BUILD_ID)
                        .withValue(new ParamValue(String.valueOf(config.getBrewBuildId())))
                        .build());

        // Add CBOM params if specified
        java.util.List<io.fabric8.tekton.v1beta1.Param> allParams = new java.util.ArrayList<>(params);

        if (config.getCbom() != null) {
            allParams.add(
                    new ParamBuilder().withName(PARAM_CBOM)
                            .withValue(new ParamValue(String.valueOf(config.getCbom())))
                            .build());
        }

        if (config.getCbomTimeout() != null && !config.getCbomTimeout().isEmpty()) {
            allParams.add(
                    new ParamBuilder().withName(PARAM_CBOM_TIMEOUT)
                            .withValue(new ParamValue(config.getCbomTimeout()))
                            .build());
        }

        return new TaskRunBuilder().withNewMetadata()
                .withNamespace(generationRequest.getMetadata().getNamespace())
                .withAnnotations(annotations)
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
                .withParams(allParams)
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
