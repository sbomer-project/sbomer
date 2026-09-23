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
package org.jboss.sbomer.service.scheduler;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.jboss.sbomer.core.features.sbom.enums.GenerationResult;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationStatus;
import org.jboss.sbomer.service.feature.sbom.model.SbomGenerationRequest;
import org.jboss.sbomer.service.feature.sbom.service.SbomGenerationRequestRepository;
import org.jboss.sbomer.service.leader.LeaderManager;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.quarkus.scheduler.Scheduled;
import io.quarkus.scheduler.Scheduled.ConcurrentExecution;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.transaction.Transactional.TxType;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * Periodically fails generations that have been stuck in a non-terminal status for longer than
 * {@link GenerationReaperConfig#timeout()} (default 24h).
 * </p>
 *
 * <p>
 * The legacy Tekton-operator generation flow transitions a generation to {@code FAILED}/{@code FINISHED} only in
 * response to Kubernetes events for the backing TaskRun. If a TaskRun is never created (e.g. quota, admission or PVC
 * issues) or its terminal event is never delivered to the operator informer, the generation stays in
 * {@code NEW}/{@code SCHEDULED}/{@code GENERATING} forever. Because a parent request event only reaches a terminal
 * state once <em>all</em> of its child generations are terminal, a single stuck child pins the whole request at "in
 * progress" indefinitely -- there was previously no application-level backstop other than the 6h Tekton TaskRun timeout
 * (which itself depends on the operator observing the transition).
 * </p>
 *
 * <p>
 * This reaper is that backstop. For each stuck generation it records what happened (the status it was stuck in and for
 * how long, and whether the backing ConfigMap still existed) in the generation's {@code reason}, deletes the stale
 * ConfigMap so the operator stops tracking it, marks the generation {@code FAILED} and re-evaluates the parent request
 * event so it can finally reach a terminal state.
 * </p>
 */
@ApplicationScoped
@Slf4j
public class GenerationRequestReaper {

    private final SbomGenerationRequestRepository requestRepository;

    private final KubernetesClient kubernetesClient;

    private final GenerationReaperConfig config;

    private final LeaderManager leaderManager;

    /**
     * Self-injected proxy so that {@link #failStuckGeneration(String)} runs in its own transaction; a failure handling
     * one stuck generation must not roll back or block the handling of the others.
     */
    @Inject
    GenerationRequestReaper self;

    @Inject
    public GenerationRequestReaper(
            SbomGenerationRequestRepository requestRepository,
            KubernetesClient kubernetesClient,
            GenerationReaperConfig config,
            LeaderManager leaderManager) {
        this.requestRepository = requestRepository;
        this.kubernetesClient = kubernetesClient;
        this.config = config;
        this.leaderManager = leaderManager;
    }

    /**
     * <p>
     * Finds and fails generations that have been stuck in a non-terminal status past the configured timeout.
     * </p>
     *
     * <p>
     * Runs periodically (default every 10 minutes, controlled by {@code sbomer.service.generation-reaper.interval}) and
     * only on the leader instance.
     * </p>
     */
    @Scheduled(
            every = "${sbomer.service.generation-reaper.interval:10m}",
            delay = 2,
            delayUnit = TimeUnit.MINUTES,
            concurrentExecution = ConcurrentExecution.SKIP)
    public void reapStuckGenerations() {
        if (!config.enabled()) {
            log.debug("Generation reaper is disabled, skipping");
            return;
        }

        if (!leaderManager.isLeader()) {
            log.debug("Current instance is not the leader, skipping reaping of stuck generations in this instance");
            return;
        }

        Instant cutoff = Instant.now().minus(config.timeout());

        List<SbomGenerationRequest> stuck = requestRepository.findStuckGenerations(cutoff);

        if (stuck.isEmpty()) {
            log.debug("No generations stuck for longer than {} found", config.timeout());
            return;
        }

        log.warn(
                "Found {} generation(s) stuck in a non-terminal status for longer than {}, failing them",
                stuck.size(),
                config.timeout());

        List<String> reaped = new ArrayList<>();
        for (SbomGenerationRequest generation : stuck) {
            String id = generation.getId();
            try {
                self.failStuckGeneration(id);
                reaped.add(id);
            } catch (Exception e) {
                // Never let one problematic generation stop us from reaping the rest.
                log.error("Failed to reap stuck generation '{}'", id, e);
            }
        }

        log.warn("Reaper failed {} stuck generation(s): {}", reaped.size(), reaped);
    }

    /**
     * Fails a single stuck generation in its own transaction: deletes its stale ConfigMap (if any), marks it
     * {@code FAILED} with a diagnostic reason and re-evaluates the parent request event.
     *
     * @param id the id of the generation to fail
     */
    @Transactional(value = TxType.REQUIRES_NEW)
    public void failStuckGeneration(String id) {
        SbomGenerationRequest generation = requestRepository.findById(id);

        if (generation == null) {
            log.debug("Generation '{}' no longer exists, nothing to reap", id);
            return;
        }

        // It may have reached a terminal state between the query and now (e.g. a late TaskRun event was observed).
        if (generation.getStatus().isFinal()) {
            log.debug(
                    "Generation '{}' reached final status {} before it could be reaped, skipping",
                    id,
                    generation.getStatus());
            return;
        }

        SbomGenerationStatus stuckStatus = generation.getStatus();
        Duration age = Duration.between(generation.getCreationTime(), Instant.now());

        String configMapName = "sbom-request-" + id.toLowerCase();
        boolean configMapExisted = deleteConfigMap(configMapName);

        String reason = String.format(
                "Generation timed out: exceeded the maximum allowed duration of %s. It was stuck in status %s for %dh %dm before being failed by the reaper. Backing ConfigMap '%s' %s.",
                config.timeout(),
                stuckStatus,
                age.toHours(),
                age.toMinutesPart(),
                configMapName,
                configMapExisted ? "was present and has been deleted" : "was not found");

        log.warn(
                "Reaping stuck generation '{}' (identifier '{}', type {}): {}",
                id,
                generation.getIdentifier(),
                generation.getType(),
                reason);

        generation.setStatus(SbomGenerationStatus.FAILED);
        generation.setResult(GenerationResult.ERR_SYSTEM);
        generation.setReason(reason);

        // Re-evaluate the parent request event so it can leave "in progress" now that this child is terminal.
        // The generation was loaded via findById within this transaction, so it (and its associated request event)
        // are managed entities; the changes above are flushed automatically when this transaction commits.
        SbomGenerationRequest.updateRequestEventStatus(generation);
    }

    /**
     * Deletes the backing ConfigMap (and, via owner references, its dependent TaskRuns) so the operator stops tracking
     * a generation we are about to fail.
     *
     * @param configMapName the name of the ConfigMap
     * @return {@code true} if the ConfigMap existed, {@code false} otherwise
     */
    private boolean deleteConfigMap(String configMapName) {
        try {
            if (kubernetesClient.configMaps().withName(configMapName).get() == null) {
                return false;
            }
            kubernetesClient.configMaps().withName(configMapName).delete();
            log.debug("Deleted stale ConfigMap '{}'", configMapName);
            return true;
        } catch (Exception e) {
            // Deleting the ConfigMap is best-effort; failing the generation in the DB is what unsticks the request.
            log.error("Unable to delete stale ConfigMap '{}' while reaping", configMapName, e);
            return true;
        }
    }
}
