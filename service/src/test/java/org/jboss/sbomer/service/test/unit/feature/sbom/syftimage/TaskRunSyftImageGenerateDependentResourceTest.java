package org.jboss.sbomer.service.test.unit.feature.sbom.syftimage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import java.text.ParseException;
import java.util.Collections;

import org.jboss.sbomer.core.features.sbom.config.SyftImageConfig;
import org.jboss.sbomer.core.features.sbom.enums.GenerationRequestType;
import org.jboss.sbomer.service.feature.FeatureFlags;
import org.jboss.sbomer.service.feature.sbom.k8s.model.GenerationRequest;
import org.jboss.sbomer.service.feature.sbom.k8s.model.GenerationRequestBuilder;
import org.jboss.sbomer.service.generator.image.controller.TaskRunSyftImageGenerateDependentResource;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import io.fabric8.kubernetes.api.model.Duration;
import io.fabric8.tekton.v1beta1.Param;
import io.fabric8.tekton.v1beta1.TaskRun;
import io.javaoperatorsdk.operator.api.reconciler.Context;

@SuppressWarnings("unchecked")
class TaskRunSyftImageGenerateDependentResourceTest {
    static class TaskRunSyftImageGenerateDependentResourceAlt extends TaskRunSyftImageGenerateDependentResource {

        TaskRunSyftImageGenerateDependentResourceAlt(FeatureFlags featureFlags) {
            super(TaskRun.class);

            this.release = "sbomer";
            this.featureFlags = featureFlags;
        }

        public TaskRunSyftImageGenerateDependentResourceAlt(Class<TaskRun> resourceType) {
            super(resourceType);
        }

        @Override
        public TaskRun desired(GenerationRequest generationRequest, Context<GenerationRequest> context) {
            return super.desired(generationRequest, context);
        }
    }

    @Test
    void testDefaultConfig() throws ParseException {
        FeatureFlags mockFeatureFlags = Mockito.mock(FeatureFlags.class);
        when(mockFeatureFlags.syftManifestOptEnabled()).thenReturn(false);

        TaskRunSyftImageGenerateDependentResourceAlt res = new TaskRunSyftImageGenerateDependentResourceAlt(
                mockFeatureFlags);

        GenerationRequest generationRequest = new GenerationRequestBuilder(GenerationRequestType.CONTAINERIMAGE)
                .withId("oneone")
                .withIdentifier("image-name")
                .withConfig(new SyftImageConfig())
                .build();

        Context<GenerationRequest> mockedContext = Mockito.mock(Context.class);

        TaskRun desired = res.desired(generationRequest, mockedContext);

        assertEquals("sbom-request-oneone-1-generate", desired.getMetadata().getName());
        assertEquals("sbomer-sa", desired.getSpec().getServiceAccountName());
        assertEquals(Duration.parse("6h"), desired.getSpec().getTimeout());
        assertEquals(4, desired.getSpec().getParams().size());

        Param param = desired.getSpec().getParams().get(0);
        assertEquals("image", param.getName());
        assertEquals("image-name", param.getValue().getStringVal());

        param = desired.getSpec().getParams().get(1);
        assertEquals("processors", param.getName());
        assertEquals("default", param.getValue().getStringVal());

        param = desired.getSpec().getParams().get(2);
        assertEquals("paths", param.getName());
        assertEquals(Collections.emptyList(), param.getValue().getArrayVal());

        param = desired.getSpec().getParams().get(3);
        assertEquals("rpms", param.getName());
        assertEquals("true", param.getValue().getStringVal());

        assertEquals("sbomer-generate-image-syft", desired.getSpec().getTaskRef().getName());

        assertEquals(1, desired.getSpec().getWorkspaces().size());
        assertEquals("data", desired.getSpec().getWorkspaces().get(0).getName());
    }

    @Test
    void allowToEnableRpms() {
        FeatureFlags mockFeatureFlags = Mockito.mock(FeatureFlags.class);
        when(mockFeatureFlags.syftManifestOptEnabled()).thenReturn(false);

        TaskRunSyftImageGenerateDependentResourceAlt res = new TaskRunSyftImageGenerateDependentResourceAlt(
                mockFeatureFlags);

        SyftImageConfig config = new SyftImageConfig();
        config.setIncludeRpms(true);

        GenerationRequest generationRequest = new GenerationRequestBuilder(GenerationRequestType.CONTAINERIMAGE)
                .withId("oneone")
                .withIdentifier("image-name")
                .withConfig(config)
                .build();

        Context<GenerationRequest> mockedContext = Mockito.mock(Context.class);

        TaskRun desired = res.desired(generationRequest, mockedContext);

        Param param = desired.getSpec().getParams().get(3);
        assertEquals("rpms", param.getName());
        assertEquals("true", param.getValue().getStringVal());
    }
}
