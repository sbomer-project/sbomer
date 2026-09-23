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
package org.jboss.sbomer.service.feature.sbom.service;

import java.time.Instant;
import java.util.List;

import org.jboss.sbomer.core.errors.NotFoundException;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationStatus;
import org.jboss.sbomer.service.feature.sbom.model.Sbom;
import org.jboss.sbomer.service.feature.sbom.model.SbomGenerationRequest;
import org.jboss.sbomer.service.rest.criteria.CriteriaAwareRepository;

import io.quarkus.panache.common.Parameters;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@ApplicationScoped
@Slf4j
public class SbomGenerationRequestRepository extends CriteriaAwareRepository<SbomGenerationRequest> {

    public SbomGenerationRequestRepository() {
        super(SbomGenerationRequest.class);
    }

    @Transactional
    public void deleteRequest(String id) {

        log.info("Deleting SbomGenerationRequest with id: '{}' and all its associated SBOMs", id);
        SbomGenerationRequest request = findById(id);
        if (request == null) {
            throw new NotFoundException("Could not find any SBOM generation request with id '{}'", id);
        }

        long sbomsDeletedCount = Sbom.delete("generationRequest.id = :id", Parameters.with("id", id)); // NOSONAR
        log.info("Deleted {} SBOMs associated with the Generation Request with id: '{}'", sbomsDeletedCount, id);

        SbomGenerationRequest.delete("id = :id", Parameters.with("id", id)); // NOSONAR
        log.info("Deleted the SBOM Generation Request with id: '{}'", id);

        flush();
    }

    @Transactional
    public SbomGenerationRequest save(SbomGenerationRequest generationRequest) {
        persistAndFlush(generationRequest);
        return generationRequest;
    }

    @Transactional
    public List<SbomGenerationRequest> listByIdentifier(String identifier) {
        return find("identifier = ?1", identifier).list();
    }

    /**
     * Finds generations that are stuck: they have not reached a final status ({@code FINISHED}/{@code FAILED}) and were
     * created before the given {@code cutoff}. Used by the
     * {@link org.jboss.sbomer.service.scheduler.GenerationRequestReaper} to fail generations that never terminated
     * (e.g. because a Tekton TaskRun was never created or its terminal event was never observed), which otherwise pin
     * their parent request event at "in progress" indefinitely.
     *
     * @param cutoff generations created strictly before this instant are considered
     * @return the stuck generations, oldest first
     */
    @Transactional
    public List<SbomGenerationRequest> findStuckGenerations(Instant cutoff) {
        return find(
                "status not in ?1 and creationTime < ?2 order by creationTime asc",
                List.of(SbomGenerationStatus.FINISHED, SbomGenerationStatus.FAILED),
                cutoff).list();
    }
}
