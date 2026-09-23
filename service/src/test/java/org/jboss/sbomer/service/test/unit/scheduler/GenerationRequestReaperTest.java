package org.jboss.sbomer.service.test.unit.scheduler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.jboss.sbomer.core.features.sbom.enums.GenerationRequestType;
import org.jboss.sbomer.core.features.sbom.enums.GenerationResult;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationStatus;
import org.jboss.sbomer.service.feature.sbom.model.SbomGenerationRequest;
import org.jboss.sbomer.service.feature.sbom.service.SbomGenerationRequestRepository;
import org.jboss.sbomer.service.leader.LeaderManager;
import org.jboss.sbomer.service.scheduler.GenerationReaperConfig;
import org.jboss.sbomer.service.scheduler.GenerationRequestReaper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapList;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.dsl.MixedOperation;
import io.fabric8.kubernetes.client.dsl.Resource;

public class GenerationRequestReaperTest {

    KubernetesClient kubernetesClient;

    SbomGenerationRequestRepository requestRepository;

    GenerationReaperConfig config;

    LeaderManager leaderManager;

    GenerationRequestReaper reaper;

    @BeforeEach
    void beforeEach() {
        config = mock(GenerationReaperConfig.class);
        when(config.enabled()).thenReturn(true);
        when(config.timeout()).thenReturn(Duration.ofHours(24));
        when(config.interval()).thenReturn("10m");

        leaderManager = mock(LeaderManager.class);
        requestRepository = mock(SbomGenerationRequestRepository.class);
        kubernetesClient = mock(KubernetesClient.class, RETURNS_DEEP_STUBS);

        reaper = spy(new GenerationRequestReaper(requestRepository, kubernetesClient, config, leaderManager));
        // Self-injection is a CDI concern; wire the (package-private) field manually for the unit test.
        setSelf(reaper, reaper);
    }

    private static void setSelf(GenerationRequestReaper reaper, GenerationRequestReaper self) {
        try {
            java.lang.reflect.Field field = GenerationRequestReaper.class.getDeclaredField("self");
            field.setAccessible(true);
            field.set(reaper, self);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Unable to wire self-injection for test", e);
        }
    }

    @Test
    void shouldDoNothingIfDisabled() {
        when(config.enabled()).thenReturn(false);

        reaper.reapStuckGenerations();

        verifyNoInteractions(leaderManager);
        verifyNoInteractions(requestRepository);
    }

    @Test
    void shouldDoNothingIfWeAreNotTheLeader() {
        when(leaderManager.isLeader()).thenReturn(false);

        reaper.reapStuckGenerations();

        verifyNoInteractions(requestRepository);
    }

    @Test
    void shouldDoNothingIfNoStuckGenerations() {
        when(leaderManager.isLeader()).thenReturn(true);
        when(requestRepository.findStuckGenerations(Mockito.any())).thenReturn(List.of());

        reaper.reapStuckGenerations();

        verify(reaper, never()).failStuckGeneration(anyString());
    }

    @Test
    void shouldFailEachStuckGeneration() {
        when(leaderManager.isLeader()).thenReturn(true);
        when(requestRepository.findStuckGenerations(Mockito.any()))
                .thenReturn(List.of(generation("GEN1"), generation("GEN2")));
        doNothing().when(reaper).failStuckGeneration(anyString());

        reaper.reapStuckGenerations();

        verify(reaper).failStuckGeneration("GEN1");
        verify(reaper).failStuckGeneration("GEN2");
    }

    @Test
    void shouldKeepReapingWhenOneGenerationFails() {
        when(leaderManager.isLeader()).thenReturn(true);
        when(requestRepository.findStuckGenerations(Mockito.any()))
                .thenReturn(List.of(generation("GEN1"), generation("GEN2")));
        doThrow(new RuntimeException("boom")).when(reaper).failStuckGeneration("GEN1");
        doNothing().when(reaper).failStuckGeneration("GEN2");

        reaper.reapStuckGenerations();

        // Even though GEN1 blew up, GEN2 must still be attempted.
        verify(reaper).failStuckGeneration("GEN1");
        verify(reaper).failStuckGeneration("GEN2");
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldFailStuckGenerationAndDeleteConfigMap() {
        SbomGenerationRequest generation = generation("GEN1");

        String configMapName = "sbom-request-gen1";
        MixedOperation<ConfigMap, ConfigMapList, Resource<ConfigMap>> configMaps = mock(MixedOperation.class);
        Resource<ConfigMap> configMapResource = mock(Resource.class);
        when(kubernetesClient.configMaps()).thenReturn(configMaps);
        when(configMaps.withName(configMapName)).thenReturn(configMapResource);
        when(configMapResource.get()).thenReturn(new ConfigMap());

        when(requestRepository.findById("GEN1")).thenReturn(generation);

        try (MockedStatic<SbomGenerationRequest> statc = Mockito.mockStatic(SbomGenerationRequest.class)) {
            reaper.failStuckGeneration("GEN1");

            assertEquals(SbomGenerationStatus.FAILED, generation.getStatus());
            assertEquals(GenerationResult.ERR_SYSTEM, generation.getResult());
            assertNotNull(generation.getReason());
            assertTrue(generation.getReason().contains("timed out"));
            assertTrue(generation.getReason().contains("GENERATING"));
            assertTrue(generation.getReason().contains("has been deleted"));

            // The stale ConfigMap must be deleted and the parent request event re-evaluated.
            verify(configMapResource).delete();
            statc.verify(() -> SbomGenerationRequest.updateRequestEventStatus(generation));
        }
    }

    @Test
    void shouldNotFailGenerationThatAlreadyReachedTerminalStatus() {
        SbomGenerationRequest generation = generation("GEN1");
        generation.setStatus(SbomGenerationStatus.FINISHED);
        generation.setResult(GenerationResult.SUCCESS);

        when(requestRepository.findById("GEN1")).thenReturn(generation);

        try (MockedStatic<SbomGenerationRequest> statc = Mockito.mockStatic(SbomGenerationRequest.class)) {
            reaper.failStuckGeneration("GEN1");

            // Untouched: still FINISHED, parent not re-evaluated, no ConfigMap interaction.
            assertEquals(SbomGenerationStatus.FINISHED, generation.getStatus());
            assertEquals(GenerationResult.SUCCESS, generation.getResult());
            statc.verify(() -> SbomGenerationRequest.updateRequestEventStatus(Mockito.any()), never());
            verifyNoInteractions(kubernetesClient);
        }
    }

    private static SbomGenerationRequest generation(String id) {
        SbomGenerationRequest generation = new SbomGenerationRequest();
        generation.setId(id);
        generation.setType(GenerationRequestType.BREW_RPM);
        generation.setIdentifier(id + "-identifier");
        generation.setStatus(SbomGenerationStatus.GENERATING);
        generation.setCreationTime(Instant.now().minus(Duration.ofHours(30)));
        return generation;
    }
}
