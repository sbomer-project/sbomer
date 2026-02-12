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
package org.jboss.sbomer.service.feature.sbom.errata.event.release;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.cyclonedx.model.Component;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.component.evidence.Identity;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.enums.RequestEventStatus;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.service.feature.FeatureFlags;
import org.jboss.sbomer.service.feature.errors.FeatureDisabledException;
import org.jboss.sbomer.service.feature.sbom.atlas.AtlasHandler;
import org.jboss.sbomer.service.feature.sbom.errata.ErrataClient;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationStatus;
import org.jboss.sbomer.service.feature.sbom.model.RequestEvent;
import org.jboss.sbomer.service.feature.sbom.model.Sbom;
import org.jboss.sbomer.service.feature.sbom.model.SbomGenerationRequest;
import org.jboss.sbomer.service.feature.sbom.service.RequestEventRepository;
import org.jboss.sbomer.service.feature.sbom.service.SbomGenerationRequestRepository;
import org.jboss.sbomer.service.feature.sbom.service.SbomService;
import org.jboss.sbomer.service.rest.otel.TracingRestClient;
import org.jboss.sbomer.service.stats.StatsService;

import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@Setter
@Slf4j
public class AbstractEventsListener {

    // Set the long transaction timeout to 10 minutes
    protected static final int INCREASED_TIMEOUT_SEC = 600;

    public static final String REQUEST_ID = "request_id";
    public static final String ERRATA = "errata_fullname";
    public static final String ERRATA_ID = "errata_id";
    public static final String ERRATA_SHIP_DATE = "errata_ship_date";
    public static final String PRODUCT = "product_name";
    public static final String PRODUCT_SHORTNAME = "product_shortname";
    public static final String PRODUCT_VERSION = "product_version";
    public static final String PURL_LIST = "purl_list";

    @Inject
    @TracingRestClient
    protected ErrataClient errataClient;

    @Inject
    protected SbomService sbomService;

    @Inject
    protected StatsService statsService;

    @Inject
    protected SbomGenerationRequestRepository generationRequestRepository;

    @Inject
    protected RequestEventRepository requestEventRepository;

    @Inject
    AtlasHandler atlasHandler;

    @Inject
    protected FeatureFlags featureFlags;

    @Transactional(value = Transactional.TxType.REQUIRES_NEW)
    protected void markRequestFailed(
            RequestEvent requestEvent,
            Collection<SbomGenerationRequest> releaseGenerations,
            String reason) {
        log.error(reason);

        requestEvent = requestEventRepository.findById(requestEvent.getId());
        requestEvent.setEventStatus(RequestEventStatus.FAILED);
        requestEvent.setReason(reason);

        for (SbomGenerationRequest generation : releaseGenerations) {
            generation = generationRequestRepository.findById(generation.getId());
            generation.setStatus(SbomGenerationStatus.FAILED);
            generation.setReason(reason);
        }
    }

    @Transactional
    protected void doUpdateGenerationsStatus(Collection<SbomGenerationRequest> releaseGenerations) {
        // Update only one SbomGenerationRequest, because the requestEvent associated is the same for all of them. This
        // avoids duplicated comments in the advisory
        if (releaseGenerations != null && !releaseGenerations.isEmpty()) {
            SbomGenerationRequest generation = releaseGenerations.iterator().next();
            generation = generationRequestRepository.findById(generation.getId());
            SbomGenerationRequest.updateRequestEventStatus(generation);
        }
    }

    protected Metadata createMetadata(
            String name,
            String version,
            Component.Type type,
            Set<String> cpes,
            Date shipDate,
            String toolVersion) {
        Metadata metadata = new Metadata();

        Component metadataProductComponent = SbomUtils.createComponent(null, name, version, null, null, type);
        metadataProductComponent.setBomRef(version);
        SbomUtils.setSupplier(metadataProductComponent);
        SbomUtils.setEvidenceIdentities(metadataProductComponent, cpes, Identity.Field.CPE);

        metadata.setComponent(metadataProductComponent);
        if (shipDate != null) {
            metadata.setTimestamp(shipDate);
        }
        metadata.setToolChoice(SbomUtils.createToolInformation(toolVersion));
        return metadata;
    }

    protected void performPost(List<Sbom> sboms) {
        try {
            atlasHandler.publishReleaseManifests(sboms);
        } catch (FeatureDisabledException e) {
            log.warn(e.getMessage(), e);
        } catch (Exception e) {
            throw new ApplicationException("Atlas upload failed: {}", e.getMessage(), e);
        }
    }

}
