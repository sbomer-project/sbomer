package org.jboss.sbomer.service.test.unit.feature.sbom.errata;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.jboss.sbomer.core.config.request.ErrataAdvisoryRequestConfig;
import org.jboss.sbomer.core.features.sbom.config.Config;
import org.jboss.sbomer.core.features.sbom.enums.GenerationRequestType;
import org.jboss.sbomer.core.features.sbom.enums.GenerationResult;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.core.test.TestResources;
import org.jboss.sbomer.service.feature.sbom.errata.ErrataClient;
import org.jboss.sbomer.service.feature.sbom.errata.event.comment.CommentAdvisoryOnRelevantEventsListener;
import org.jboss.sbomer.service.feature.sbom.errata.event.comment.RequestEventStatusUpdateEvent;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationStatus;
import org.jboss.sbomer.service.feature.sbom.model.RequestEvent;
import org.jboss.sbomer.service.feature.sbom.model.Sbom;
import org.jboss.sbomer.service.feature.sbom.model.SbomGenerationRequest;
import org.jboss.sbomer.service.feature.sbom.service.SbomService;
import org.jboss.sbomer.service.rest.otel.TracingRestClient;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.Answer;

import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.test.junit.mockito.InjectSpy;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@QuarkusTest
@TestProfile(CommentAdvisoryOnRelevantEventsListenerTest.MyCustomConfig.class)
public class CommentAdvisoryOnRelevantEventsListenerTest {

    @InjectSpy
    CommentAdvisoryOnRelevantEventsListener commentAdvisoryOnRelevantEventsListener;

    @InjectMock
    SbomService sbomService;

    @InjectMock
    @TracingRestClient
    ErrataClient errataClient;

    public static class MyCustomConfig implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("SBOMER_ROUTE_HOST", "sbomer.redhat.com");
        }
    }

    private SbomGenerationRequest createFailedGeneration() {
        return SbomGenerationRequest.builder()
                .withId("006CE39D4EF54A7")
                .withIdentifier(
                        "registry-proxy.engineering.redhat.com/rh-osbs/openshift-ose-ovn-kubernetes-rhel9@sha256:66a790bc5a63f647a6d36d241f0260a5f1b619ae009a7c73daf17bab6f1445d4")
                .withStatus(SbomGenerationStatus.FAILED)
                .withCreationTime(Instant.now())
                .withConfig(
                        Config.fromString(
                                "{\"rpms\":true,\"type\":\"syft-image\",\"image\":\"registry-proxy.engineering.redhat.com/rh-osbs/openshift-ose-ovn-kubernetes-rhel9@sha256:66a790bc5a63f647a6d36d241f0260a5f1b619ae009a7c73daf17bab6f1445d4\",\"paths\":[],\"apiVersion\":\"sbomer.jboss.org/v1alpha1\",\"processors\":[]}"))
                .withReason(
                        "Generation failed. TaskRun responsible for generation failed. See logs for more information.")
                .withResult(GenerationResult.ERR_SYSTEM)
                .withType(GenerationRequestType.CONTAINERIMAGE)
                .withRequest(RequestEvent.builder().withId("E60FF59A42544B3").build())
                .build();
    }

    private SbomGenerationRequest createSuccessfulGeneration() {
        return SbomGenerationRequest.builder()
                .withId("E2C857A8C98D440")
                .withIdentifier(
                        "registry-proxy.engineering.redhat.com/rh-osbs/openshift-ose-csi-driver-manila-operator-rhel9@sha256:2808208e87226be9a9d81cf49013f508e534c9135ba8bfdd8ba596d9a321948c")
                .withStatus(SbomGenerationStatus.FINISHED)
                .withCreationTime(Instant.now())
                .withConfig(
                        Config.fromString(
                                "{\"rpms\":true,\"type\":\"syft-image\",\"image\":\"registry-proxy.engineering.redhat.com/rh-osbs/openshift-ose-csi-driver-manila-operator-rhel9@sha256:2808208e87226be9a9d81cf49013f508e534c9135ba8bfdd8ba596d9a321948c\",\"paths\":[],\"apiVersion\":\"sbomer.jboss.org/v1alpha1\",\"processors\":[]}"))
                .withReason(
                        "Generation finished successfully. Generated SBOMs: F62FD36400A742D, C984974DB371432, BA944EBE26E3446")
                .withResult(GenerationResult.SUCCESS)
                .withType(GenerationRequestType.CONTAINERIMAGE)
                .withRequest(RequestEvent.builder().withId("E60FF59A42544B3").build())
                .build();
    }

    private List<SbomGenerationRequest> createPartialGenerations() {
        List<SbomGenerationRequest> generationRequests = new ArrayList<>();
        generationRequests.add(createFailedGeneration());
        generationRequests.add(createSuccessfulGeneration());
        return generationRequests;
    }

    private Sbom createSuccessfulSbom() throws IOException {
        return Sbom.builder()
                .withId("BA944EBE26E3446")
                .withIdentifier(
                        "registry-proxy.engineering.redhat.com/rh-osbs/openshift-ose-csi-driver-manila-operator-rhel9@sha256:2808208e87226be9a9d81cf49013f508e534c9135ba8bfdd8ba596d9a321948c")
                .withRootPurl(
                        "pkg:oci/ose-csi-driver-manila-operator-rhel9@sha256%3A36234273400823174d6d55cbe13eed40fb19e23069aca9cac43958f8be7c2a53?arch=ppc64le&os=linux&tag=v4.17.0-202504091537.p0.gefc99a2.assembly.stream.el9")
                .withCreationTime(Instant.now())
                .withSbom(SbomUtils.toJsonNode(TestResources.asString("sboms/BA944EBE26E3446.json")))
                .withGenerationRequest(createSuccessfulGeneration())
                .build();
    }

    @Test
    void testHandleAutomatedManifestationAdvisory() throws IOException {

        when(sbomService.findByGenerationRequest("E2C857A8C98D440")).thenReturn(createSuccessfulSbom());

        // Prepare test data
        RequestEventStatusUpdateEvent event = RequestEventStatusUpdateEvent.builder()
                .withRequestEventId("E60FF59A42544B3")
                .build();
        ErrataAdvisoryRequestConfig config = ErrataAdvisoryRequestConfig.builder().withAdvisoryId("148016").build();
        doReturn(createPartialGenerations()).when(commentAdvisoryOnRelevantEventsListener)
                .findGenerationsByRequest(any());

        // Capture outputs of the methods
        AtomicReference<String> summarySection = new AtomicReference<>();
        AtomicReference<String> finishedSection = new AtomicReference<>();
        AtomicReference<String> failedSection = new AtomicReference<>();

        // Stub createSummaryStatusSection to capture its output
        doAnswer((Answer<String>) invocation -> {
            String result = (String) invocation.callRealMethod();
            summarySection.set(result);
            return result;
        }).when(commentAdvisoryOnRelevantEventsListener).createSummaryStatusSection(any());

        // Stub createGenerationsSectionForStatus for FINISHED status
        doAnswer((Answer<String>) invocation -> {
            String result = (String) invocation.callRealMethod();
            finishedSection.set(result);
            return result;
        }).when(commentAdvisoryOnRelevantEventsListener)
                .createGenerationsSectionForStatus(any(), any(), eq(SbomGenerationStatus.FINISHED), anyString());

        // Stub createGenerationsSectionForStatus for FAILED status
        doAnswer((Answer<String>) invocation -> {
            String result = (String) invocation.callRealMethod();
            failedSection.set(result);
            return result;
        }).when(commentAdvisoryOnRelevantEventsListener)
                .createGenerationsSectionForStatus(any(), any(), eq(SbomGenerationStatus.FAILED), anyString());

        commentAdvisoryOnRelevantEventsListener.handleAutomatedManifestationAdvisory(event, config);

        verify(sbomService, times(1)).findByGenerationRequest("E2C857A8C98D440");

        // Assert the captured outputs
        assertEquals("2 builds manifested. 1 generations succeeded, 1 failed.\n\n", summarySection.get());
        assertEquals(
                "\nSucceeded generations:\n\ncsi-driver-manila-operator-container-v4.17.0-202504091537.p0.gefc99a2.assembly.stream.el9: https://sbomer.redhat.com/generations/E2C857A8C98D440",
                finishedSection.get());
        assertEquals(
                "\nFailed generations:\n\nregistry-proxy.engineering.redhat.com/rh-osbs/openshift-ose-ovn-kubernetes-rhel9@sha256:66a790bc5a63f647a6d36d241f0260a5f1b619ae009a7c73daf17bab6f1445d4: https://sbomer.redhat.com/generations/006CE39D4EF54A7",
                failedSection.get());
    }

}
