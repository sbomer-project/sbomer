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
package org.jboss.sbomer.service.feature.sbom.k8s.reconciler.condition;

import org.jboss.sbomer.core.features.sbom.enums.GenerationRequestType;
import org.jboss.sbomer.service.feature.sbom.k8s.model.GenerationRequest;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationStatus;

import io.fabric8.tekton.v1beta1.TaskRun;
import io.javaoperatorsdk.operator.api.reconciler.Context;
import io.javaoperatorsdk.operator.api.reconciler.dependent.DependentResource;
import io.javaoperatorsdk.operator.processing.dependent.workflow.Condition;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class IsBuildTypeCondition implements Condition<TaskRun, GenerationRequest> {

    @Override
    public boolean isMet(
            DependentResource<TaskRun, GenerationRequest> dependentResource,
            GenerationRequest primary,
            Context<GenerationRequest> context) {

        if (!GenerationRequestType.BUILD.equals(primary.getType())) {
            log.trace("Current generation request type: {} is not {}", primary.getType(), GenerationRequestType.BUILD);
            return false;
        }

        // Only reconcile the init TaskRun when status is SCHEDULED or INITIALIZING
        // Once INITIALIZED or beyond, the init TaskRun is complete and should not be updated
        if (primary.getStatus() == null) {
            log.trace("Status is null, not ready for init reconciliation");
            return false;
        }

        boolean shouldReconcile = primary.getStatus().equals(SbomGenerationStatus.SCHEDULED)
                || primary.getStatus().equals(SbomGenerationStatus.INITIALIZING);

        if (!shouldReconcile) {
            log.trace(
                    "Resource status is {}, which is beyond initialization phase. Init TaskRun should not be reconciled.",
                    primary.getStatus());
        }

        return shouldReconcile;
    }
}
