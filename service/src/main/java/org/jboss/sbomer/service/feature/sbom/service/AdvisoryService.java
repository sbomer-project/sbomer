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

import static org.jboss.sbomer.core.features.sbom.utils.MDCUtils.MDC_SPAN_ID_KEY;
import static org.jboss.sbomer.core.features.sbom.utils.MDCUtils.MDC_TRACEPARENT_KEY;
import static org.jboss.sbomer.core.features.sbom.utils.MDCUtils.MDC_TRACE_ID_KEY;
import static org.jboss.sbomer.service.feature.sbom.errata.event.EventNotificationFiringUtil.notifyAdvisoryRelease;
import static org.jboss.sbomer.service.feature.sbom.errata.event.EventNotificationFiringUtil.notifyRequestEventStatusUpdate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import org.eclipse.microprofile.context.ManagedExecutor;
import org.eclipse.microprofile.faulttolerance.Retry;
import org.jboss.pnc.build.finder.koji.KojiClientSession;
import org.jboss.pnc.common.Strings;
import org.jboss.sbomer.core.SchemaValidator.ValidationResult;
import org.jboss.sbomer.core.config.request.ErrataAdvisoryRequestConfig;
import org.jboss.sbomer.core.config.request.PncAnalysisRequestConfig;
import org.jboss.sbomer.core.config.request.PncBuildRequestConfig;
import org.jboss.sbomer.core.config.request.PncOperationRequestConfig;
import org.jboss.sbomer.core.config.request.RequestConfig;
import org.jboss.sbomer.core.dto.v1beta1.V1Beta1RequestRecord;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.errors.ClientException;
import org.jboss.sbomer.core.features.sbom.config.BrewRPMConfig;
import org.jboss.sbomer.core.features.sbom.config.DeliverableAnalysisConfig;
import org.jboss.sbomer.core.features.sbom.config.OperationConfig;
import org.jboss.sbomer.core.features.sbom.config.SyftImageConfig;
import org.jboss.sbomer.core.features.sbom.enums.GenerationRequestType;
import org.jboss.sbomer.core.features.sbom.enums.RequestEventStatus;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.sbomer.core.rest.faulttolerance.RetryLogger;
import org.jboss.sbomer.service.feature.FeatureFlags;
import org.jboss.sbomer.service.feature.sbom.errata.ErrataClient;
import org.jboss.sbomer.service.feature.sbom.errata.ErrataNotesSchemaValidator;
import org.jboss.sbomer.service.feature.sbom.errata.dto.Errata;
import org.jboss.sbomer.service.feature.sbom.errata.dto.Errata.Details;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataBuildList;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataBuildList.Build;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataBuildList.BuildItem;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataBuildList.ProductVersionEntry;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataProduct;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataRelease;
import org.jboss.sbomer.service.feature.sbom.errata.dto.enums.ErrataStatus;
import org.jboss.sbomer.service.feature.sbom.errata.event.comment.RequestEventStatusUpdateEvent;
import org.jboss.sbomer.service.feature.sbom.errata.event.release.StandardAdvisoryReleaseEvent;
import org.jboss.sbomer.service.feature.sbom.errata.event.release.TextOnlyAdvisoryReleaseEvent;
import org.jboss.sbomer.service.feature.sbom.k8s.model.GenerationRequest;
import org.jboss.sbomer.service.feature.sbom.k8s.model.GenerationRequestBuilder;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationStatus;
import org.jboss.sbomer.service.feature.sbom.model.RandomStringIdGenerator;
import org.jboss.sbomer.service.feature.sbom.model.RequestEvent;
import org.jboss.sbomer.service.feature.sbom.model.SbomGenerationRequest;
import org.jboss.sbomer.service.rest.otel.TracingRestClient;
import org.slf4j.MDC;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.redhat.red.build.koji.KojiClientException;
import com.redhat.red.build.koji.model.xmlrpc.KojiBuildInfo;
import com.redhat.red.build.koji.model.xmlrpc.KojiIdOrName;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.smallrye.faulttolerance.api.BeforeRetry;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.transaction.Transactional.TxType;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@ApplicationScoped
@Slf4j
public class AdvisoryService {

    @Inject
    @TracingRestClient
    @Setter
    ErrataClient errataClient;

    @Inject
    Instance<KojiClientSession> kojiSessionInstance;

    KojiClientSession kojiSession;

    @Inject
    KubernetesClient kubernetesClient;

    @Inject
    @Setter
    SbomService sbomService;

    @Inject
    RequestEventRepository requestEventRepository;

    @Inject
    SbomGenerationRequestRepository generationRequestRepository;

    @Inject
    @Setter
    FeatureFlags featureFlags;

    @Inject
    ErrataNotesSchemaValidator notesSchemaValidator;

    @Inject
    ManagedExecutor managedExecutor;

    public Collection<SbomGenerationRequest> generateFromAdvisory(RequestEvent requestEvent) {

        ErrataAdvisoryRequestConfig advisoryRequestConfig = (ErrataAdvisoryRequestConfig) requestEvent
                .getRequestConfig();

        // Fetching Erratum
        Errata erratum = errataClient.getErratum(advisoryRequestConfig.getAdvisoryId());

        if (erratum == null) {
            throw new ClientException(
                    "Could not retrieve the errata advisory with provided id {} because erratum was null",
                    advisoryRequestConfig.getAdvisoryId());
        }

        Optional<Details> optDetails = erratum.getDetails();

        if (optDetails.isEmpty()) {
            throw new ClientException(
                    "Could not retrieve the errata advisory with provided id {} because details were null",
                    advisoryRequestConfig.getAdvisoryId());
        }

        Details details = optDetails.get();

        // Will be removed, leave now for debugging
        printAllErratumData(erratum);

        if (!Boolean.TRUE.equals(details.getTextonly())) {
            return handleStandardAdvisory(requestEvent, erratum);
        } else {
            return handleTextOnlyAdvisory(requestEvent, erratum);
        }
    }

    /*
     * Event will be ignored. Useful both for REST and UMB request events (won't leave the requestEvent as IN_PROGRESS)
     */
    protected Collection<SbomGenerationRequest> doIgnoreRequest(RequestEvent requestEvent, String reason) {
        log.debug(reason);
        updateRequest(requestEvent, RequestEventStatus.IGNORED, reason);
        return Collections.emptyList();
    }

    /*
     * The event will be marked as failed. This is mostly useful for REST events (the AmqpMessageConsumer will catch the
     * exception and reupdate this request as FAILED)
     */
    protected Collection<SbomGenerationRequest> doFailRequest(RequestEvent requestEvent, String reason)
            throws ApplicationException {
        log.error(reason);
        updateRequest(requestEvent, RequestEventStatus.FAILED, reason);
        throw new ApplicationException(reason);
    }

    @Transactional(value = TxType.REQUIRES_NEW)
    protected void updateRequest(RequestEvent requestEvent, RequestEventStatus status, String reason) {
        requestEventRepository.updateRequestEvent(requestEvent, status, Map.of(), reason);
    }

    // FIXME: 'Optional.get()' without 'isPresent()' check
    private Collection<SbomGenerationRequest> handleTextOnlyAdvisory(RequestEvent requestEvent, Errata erratum) {

        // Check release flag for simplicity too, because release logic is below this condition and is toggled
        // separately
        if (!featureFlags.textOnlyErrataManifestGenerationEnabled()
                && !featureFlags.textOnlyErrataReleaseManifestGenerationEnabled()) {
            return doIgnoreRequest(requestEvent, "Text-Only Errata manifest generation is disabled");
        }

        Optional<JsonNode> maybeNotes = erratum.getNotesMapping();
        if (maybeNotes.isEmpty()) {
            String reason = String.format(
                    "Text-Only Errata Advisory '%s'(%s) does not have a Json-formatted notes field",
                    erratum.getDetails().get().getFulladvisory(),
                    erratum.getDetails().get().getId());

            return doIgnoreRequest(requestEvent, reason);
        }

        ValidationResult validationResult = notesSchemaValidator.validate(erratum);
        if (!validationResult.isValid()) {

            String reason = String.format(
                    "Text-Only Errata Advisory '%s'(%s) does not have a valid Json-formatted notes field",
                    erratum.getDetails().get().getFulladvisory(),
                    erratum.getDetails().get().getId());

            return doIgnoreRequest(requestEvent, reason);
        }

        JsonNode notes = maybeNotes.get();

        // The SBOMs are manually provided inside the "notes" field "manifest" as a list of purls
        if (notes.has("manifest")) {

            log.debug(
                    "Text-Only Errata Advisory '{}'({}) has a \"manifest\" Notes field",
                    erratum.getDetails().get().getFulladvisory(),
                    erratum.getDetails().get().getId());

            if (ErrataStatus.SHIPPED_LIVE.equals(erratum.getDetails().get().getStatus())) {

                if (!featureFlags.textOnlyErrataReleaseManifestGenerationEnabled()) {
                    return doIgnoreRequest(requestEvent, "Text Only Errata release manifest generation is disabled");
                }

                // We can proceed with the release event notification, we trust the owners of the advisory to push live
                // when appropriate
                String cpeText = erratum.getContent().getContent().getTextOnlyCpe();
                if (Strings.isEmpty(cpeText)) {
                    String reason = String.format(
                            "Text-Only Errata Advisory '%s'(%s) does not have CPE configured",
                            erratum.getDetails().get().getFulladvisory(),
                            erratum.getDetails().get().getId());

                    return doIgnoreRequest(requestEvent, reason);
                }

                Map<String, SbomGenerationRequest> releaseGenerations = createReleaseManifestsGenerationsForType(
                        erratum,
                        requestEvent,
                        Set.of(cpeText),
                        GenerationRequestType.BUILD);

                // Send an async notification for the release event
                notifyAdvisoryRelease(
                        TextOnlyAdvisoryReleaseEvent.builder()
                                .withRequestEventId(requestEvent.getId())
                                .withReleaseGenerations(releaseGenerations)
                                .build());

                return releaseGenerations.values();

            } else if (ErrataStatus.QE.equals(erratum.getDetails().get().getStatus())) {

                // Send an async notification for the completed generations (will be used to add comments to Errata)
                notifyRequestEventStatusUpdate(
                        RequestEventStatusUpdateEvent.builder()
                                .withRequestEventConfig(
                                        ErrataAdvisoryRequestConfig.builder()
                                                .withAdvisoryId(String.valueOf(erratum.getDetails().get().getId()))
                                                .build())
                                .withRequestEventStatus(RequestEventStatus.SUCCESS)
                                .build());
            }

            // There is nothing to do for SBOMer besides adding comments to the Errata
            updateRequest(requestEvent, RequestEventStatus.SUCCESS, null);

            return Collections.emptyList();
        } else {
            // The notes contain 1 or more configurations inside a "deliverables" field that SBOMer needs to handle by
            // converting them to generations
            log.debug(
                    "Text-Only Errata Advisory '{}'({}) has a \"deliverables\" Notes field",
                    erratum.getDetails().get().getFulladvisory(),
                    erratum.getDetails().get().getId());

            // If the status is SHIPPED_LIVE and there is a successful generation for this advisory, create release
            // manifests.
            // Otherwise, SBOMer will default to the creation of build manifests.
            // This will change in the future!
            V1Beta1RequestRecord successfulRequestRecord = null;
            if (ErrataStatus.SHIPPED_LIVE.equals(erratum.getDetails().get().getStatus())) {

                if (!featureFlags.textOnlyErrataReleaseManifestGenerationEnabled()) {
                    return doIgnoreRequest(requestEvent, "Text Only Errata release manifest generation is disabled");
                }

                log.debug(
                        "Errata status is SHIPPED_LIVE, looking for successful request records for advisory {}",
                        erratum.getDetails().get().getId());

                successfulRequestRecord = sbomService.searchLastSuccessfulAdvisoryBuildRequestRecord(
                        requestEvent.getId(),
                        String.valueOf(erratum.getDetails().get().getId()));
            }

            // If the forceBuild flag is enabled on incoming requestConfig, we ignore any successful records found
            // in the previous code block to force a build manifest generation instead of a release.
            if (requestEvent.getRequestConfig() != null
                    && requestEvent.getRequestConfig() instanceof ErrataAdvisoryRequestConfig) {
                ErrataAdvisoryRequestConfig advisoryConfig = (ErrataAdvisoryRequestConfig) requestEvent
                        .getRequestConfig();
                if (advisoryConfig.isForceBuild()) {
                    successfulRequestRecord = null;
                    log.debug(
                            "forceBuild has been set to true in request for advisory: '{}'[{}]. Ignoring latest generations and generating build manifests again",
                            erratum.getDetails().get().getFulladvisory(),
                            erratum.getDetails().get().getId());
                }
            }

            if (successfulRequestRecord == null) {
                List<RequestConfig> requestConfigsWithinNotes = parseRequestConfigsFromJsonNotes(
                        notes,
                        requestEvent,
                        erratum);
                return processRequestConfigsWithinNotes(requestEvent, requestConfigsWithinNotes);
            } else {
                // We can proceed with the release event notification, we trust the owners of the advisory to push live
                // when appropriate
                String cpeText = erratum.getContent().getContent().getTextOnlyCpe();
                if (Strings.isEmpty(cpeText)) {
                    String reason = String.format(
                            "Text-Only Errata Advisory '%s'(%s) does not have CPE configured",
                            erratum.getDetails().get().getFulladvisory(),
                            erratum.getDetails().get().getId());

                    return doIgnoreRequest(requestEvent, reason);
                }

                Map<String, SbomGenerationRequest> releaseGenerations = createReleaseManifestsGenerationsForType(
                        erratum,
                        requestEvent,
                        Set.of(cpeText),
                        GenerationRequestType.BUILD);

                // Send an async notification for the release event
                notifyAdvisoryRelease(
                        TextOnlyAdvisoryReleaseEvent.builder()
                                .withRequestEventId(requestEvent.getId())
                                .withReleaseGenerations(releaseGenerations)
                                .build());

                return releaseGenerations.values();
            }
        }
    }

    private List<RequestConfig> parseRequestConfigsFromJsonNotes(
            JsonNode notes,
            RequestEvent requestEvent,
            Errata erratum) {

        List<RequestConfig> requestConfigsWithinNotes = new ArrayList<>();
        if (notes.has("deliverables")) {
            JsonNode deliverables = notes.path("deliverables");

            if (deliverables.isArray()) {
                for (JsonNode deliverable : deliverables) {
                    String type = deliverable.path("type").asText();
                    log.debug("Processing deliverable of type: {}", type);

                    RequestConfig requestConfig = createRequestConfig(type, deliverable);
                    if (requestConfig != null) {
                        requestConfigsWithinNotes.add(requestConfig);
                    } else {
                        // While it is fine to ignore empty notes, an invalid JSON notes field should trigger an error
                        String reason = String.format(
                                "Unsupported deliverable type '%s' in Text-Only Errata Advisory '%s' (%s)",
                                type,
                                erratum.getDetails().get().getFulladvisory(),
                                erratum.getDetails().get().getId());

                        doFailRequest(requestEvent, reason);
                    }
                }
            }
        } else if (notes.has("manifest")) {

            log.debug(
                    "Text-Only Errata Advisory '{}'({}) has a \"manifest\" Notes field",
                    erratum.getDetails().get().getFulladvisory(),
                    erratum.getDetails().get().getId());
        }
        return requestConfigsWithinNotes;
    }

    private static Map<ProductVersionEntry, List<BuildItem>> getBuildDetails(ErrataBuildList buildList) {
        return buildList.getProductVersions()
                .values()
                .stream()
                .collect(
                        Collectors.toMap(
                                productVersionEntry -> productVersionEntry,
                                productVersionEntry -> productVersionEntry.getBuilds()
                                        .stream()
                                        .flatMap(build -> build.getBuildItems().values().stream())
                                        .toList()));
    }

    private Collection<SbomGenerationRequest> handleStandardAdvisory(RequestEvent requestEvent, Errata erratum) {
        log.info(
                "Advisory {} ({}) is standard (non Text-Only), with status {}",
                erratum.getDetails().get().getFulladvisory(),
                erratum.getDetails().get().getId(),
                erratum.getDetails().get().getStatus());

        Details details = erratum.getDetails().get();
        if (details.getContentTypes().size() != 1) {
            String reason = String.format(
                    "The standard errata advisory has zero or multiple content-types (%s)",
                    details.getContentTypes());
            return doIgnoreRequest(requestEvent, reason);
        }

        if (!details.hasKnownContentType()) {
            String reason = String
                    .format("The standard errata advisory has unknown content-types (%s)", details.getContentTypes());
            return doIgnoreRequest(requestEvent, reason);
        }

        String advisoryId = String.valueOf(details.getId());
        ErrataBuildList erratumBuildList = errataClient.getBuildsList(advisoryId);
        Map<ProductVersionEntry, List<BuildItem>> buildDetails = getBuildDetails(erratumBuildList);
        boolean hasBuilds = buildDetails.values().stream().anyMatch(items -> !items.isEmpty());

        // XXX: Fall back to /builds endpoint if /builds_list returned empty (e.g., module advisories)
        if (!hasBuilds) {
            log.debug("No builds from /builds_list for advisory {}, trying /builds", advisoryId);
            erratumBuildList = errataClient.getBuilds(advisoryId);
            buildDetails = getBuildDetails(erratumBuildList);
            hasBuilds = buildDetails.values().stream().anyMatch(items -> !items.isEmpty());
        }

        // The are cases where an advisory might have no builds, let's ignore them to avoid a pending request
        if (!hasBuilds) {
            String reason = "The standard errata advisory has no retrievable builds attached, skipping!";
            return doIgnoreRequest(requestEvent, reason);
        }

        // If the status is SHIPPED_LIVE and there is a successful generation for this advisory, create release
        // manifests.
        // Otherwise, SBOMer will default to the creation of build manifests.
        // This will change in the future!
        V1Beta1RequestRecord successfulRequestRecord = null;
        if (ErrataStatus.SHIPPED_LIVE.equals(details.getStatus())) {
            log.debug(
                    "Errata status is SHIPPED_LIVE, looking for successful request records for advisory {}",
                    erratum.getDetails().get().getId());
            successfulRequestRecord = sbomService.searchLastSuccessfulAdvisoryBuildRequestRecord(
                    requestEvent.getId(),
                    String.valueOf(erratum.getDetails().get().getId()));
        }

        // If the forceBuild flag is enabled on incoming requestConfig, we ignore any successful records found
        // in the previous code block to force a build manifest generation instead of a release.
        if (requestEvent.getRequestConfig() != null
                && requestEvent.getRequestConfig() instanceof ErrataAdvisoryRequestConfig) {
            ErrataAdvisoryRequestConfig advisoryConfig = (ErrataAdvisoryRequestConfig) requestEvent.getRequestConfig();
            if (advisoryConfig.isForceBuild()) {
                successfulRequestRecord = null;
                log.debug(
                        "forceBuild has been set to true in request for advisory: '{}'[{}]. Ignoring latest generations and generating build manifests again",
                        erratum.getDetails().get().getFulladvisory(),
                        erratum.getDetails().get().getId());
            }
        }

        if (details.getContentTypes().contains("docker")) {
            log.debug("Successful request records found: {}", successfulRequestRecord);

            if (successfulRequestRecord == null) {
                return createBuildManifestsForDockerBuilds(requestEvent, buildDetails);
            } else {
                return createReleaseManifestsForBuildsOfType(
                        erratum,
                        requestEvent,
                        buildDetails,
                        GenerationRequestType.CONTAINERIMAGE);
            }

        } else if (details.getContentTypes().contains("rpm") || details.getContentTypes().contains("module")) {
            if (successfulRequestRecord == null) {
                ErrataProduct product = errataClient.getProduct(details.getProduct().getShortName());
                return createBuildManifestsForRPMBuilds(requestEvent, details, product, buildDetails);
            } else {
                return createReleaseManifestsForBuildsOfType(
                        erratum,
                        requestEvent,
                        buildDetails,
                        GenerationRequestType.BREW_RPM);
            }

        } else {
            String reason = String
                    .format("The standard errata advisory has unhandled content-types (%s)", details.getContentTypes());
            return doIgnoreRequest(requestEvent, reason);
        }
    }

    @Transactional
    protected Collection<SbomGenerationRequest> processRequestConfigsWithinNotes(
            RequestEvent requestEvent,
            List<RequestConfig> requestConfigsWithinNotes) {

        List<SbomGenerationRequest> generations = new ArrayList<>();
        for (RequestConfig config : requestConfigsWithinNotes) {
            if (config instanceof PncBuildRequestConfig) {
                log.info("New PNC build request received");

                generations.add(sbomService.generateFromBuild(requestEvent, config, null));
            } else if (config instanceof PncAnalysisRequestConfig analysisConfig) {
                log.info("New PNC analysis request received");

                generations.add(
                        sbomService.generateNewOperation(
                                requestEvent,
                                DeliverableAnalysisConfig.builder()
                                        .withDeliverableUrls(analysisConfig.getUrls())
                                        .withMilestoneId(analysisConfig.getMilestoneId())
                                        .build()));
            } else if (config instanceof PncOperationRequestConfig operationConfig) {
                log.info("New PNC operation request received");

                generations.add(
                        sbomService.generateFromOperation(
                                requestEvent,
                                OperationConfig.builder().withOperationId(operationConfig.getOperationId()).build()));
            }
        }

        return generations;
    }

    /**
     * Helper method to create RequestConfig based on the deliverable type.
     */
    private RequestConfig createRequestConfig(String type, JsonNode deliverableEntry) {
        try {
            return switch (type) {
                case PncBuildRequestConfig.TYPE_NAME ->
                    ObjectMapperProvider.json().treeToValue(deliverableEntry, PncBuildRequestConfig.class);
                case PncOperationRequestConfig.TYPE_NAME ->
                    ObjectMapperProvider.json().treeToValue(deliverableEntry, PncOperationRequestConfig.class);
                case PncAnalysisRequestConfig.TYPE_NAME ->
                    ObjectMapperProvider.json().treeToValue(deliverableEntry, PncAnalysisRequestConfig.class);
                default -> null;
            };
        } catch (JsonProcessingException | IllegalArgumentException e) {
            log.error("Failed to deserialize deliverable of type '{}': {}", type, e.getMessage());
            return null;
        }
    }

    @Transactional
    protected Collection<SbomGenerationRequest> createBuildManifestsForDockerBuilds(
            RequestEvent requestEvent,
            Map<ProductVersionEntry, List<BuildItem>> buildDetails) {

        if (!featureFlags.standardErrataImageManifestGenerationEnabled()) {
            return doIgnoreRequest(requestEvent, "Standard Errata container images manifest generation is disabled");
        }

        log.debug("Creating build manifests for Docker builds: {}", buildDetails);

        Collection<SbomGenerationRequest> sbomRequests = new ArrayList<>();

        // Collect all the docker build ids so we can query Koji in one go
        List<Long> buildIds = buildDetails.values().stream().flatMap(List::stream).map(BuildItem::getId).toList();

        Map<Long, String> imageNamesFromBuilds;

        // Try to get the image names from builds, with retries handled in getImageNamesFromBuilds()
        try {
            imageNamesFromBuilds = getImageNamesFromBuilds(buildIds);
        } catch (KojiClientException e) {
            log.error("Failed to retrieve image names after retries", e);
            return doFailRequest(requestEvent, "Unable to fetch image names after retries");
        }

        imageNamesFromBuilds.forEach((buildId, imageName) -> {
            log.debug("Retrieved imageName '{}' for buildId {}", imageName, buildId);
            if (imageName != null) {
                SyftImageConfig config = SyftImageConfig.builder().withIncludeRpms(true).withImage(imageName).build();
                log.debug("Creating GenerationRequest Kubernetes resource...");
                sbomRequests.add(sbomService.generateSyftImage(requestEvent, config));
            }
        });

        return sbomRequests;
    }

    @Transactional
    protected Map<String, SbomGenerationRequest> createReleaseManifestsGenerationsForType(
            Errata erratum,
            RequestEvent requestEvent,
            // This is aquired differently for textonly advisories and cpe is used instead
            Set<String> productVersions,
            GenerationRequestType type) {

        ObjectNode otelMetadata = ObjectMapperProvider.json().createObjectNode();
        otelMetadata.put(MDC_TRACE_ID_KEY, MDC.get(MDC_TRACE_ID_KEY));
        otelMetadata.put(MDC_SPAN_ID_KEY, MDC.get(MDC_SPAN_ID_KEY));
        otelMetadata.put(MDC_TRACEPARENT_KEY, MDC.get(MDC_TRACEPARENT_KEY));

        // We need to create 1 release manifest per ProductVersion
        // We will identify the Generation with the {Errata}#{ProductVersion} identifier
        Map<String, SbomGenerationRequest> pvToGenerations = new HashMap<>();
        productVersions.forEach(pvName -> {
            SbomGenerationRequest sbomGenerationRequest = SbomGenerationRequest.builder()
                    .withId(RandomStringIdGenerator.generate())
                    .withIdentifier(erratum.getDetails().get().getFulladvisory() + "#" + pvName)
                    .withType(type)
                    .withStatus(SbomGenerationStatus.GENERATING)
                    .withConfig(null) // I really don't know what to put here
                    .withRequest(requestEvent)
                    .withOtelMetadata(otelMetadata)
                    .build();

            pvToGenerations.put(pvName, generationRequestRepository.save(sbomGenerationRequest));
        });
        return pvToGenerations;
    }

    protected Collection<SbomGenerationRequest> createReleaseManifestsForBuildsOfType(
            Errata erratum,
            RequestEvent requestEvent,
            Map<ProductVersionEntry, List<BuildItem>> buildDetails,
            GenerationRequestType type) {

        if (type.equals(GenerationRequestType.CONTAINERIMAGE)
                && !featureFlags.standardErrataImageReleaseManifestGenerationEnabled()) {
            return doIgnoreRequest(
                    requestEvent,
                    "Standard Errata container images release manifest generation is disabled");
        } else if (type.equals(GenerationRequestType.BREW_RPM)
                && !featureFlags.standardErrataRPMReleaseManifestGenerationEnabled()) {
            return doIgnoreRequest(requestEvent, "Standard Errata RPM release manifest generation is disabled");
        }

        // SBOMER-401: Verify if there are CPEs associated, some very specific standard advisories do not have them
        Set<String> allCPEs = getAllCPEsOfBuilds(buildDetails);

        if (allCPEs.isEmpty()) {
            String reason = String.format(
                    "The Standard Advisory '%s'(%s) does not have any CPE configured, ignoring the generation of the release manifest",
                    erratum.getDetails().get().getFulladvisory(),
                    erratum.getDetails().get().getId());

            return doIgnoreRequest(requestEvent, reason);
        }

        Map<String, SbomGenerationRequest> releaseGenerations = createReleaseManifestsGenerationsForType(
                erratum,
                requestEvent,
                buildDetails.keySet().stream().map(ProductVersionEntry::getName).collect(Collectors.toSet()),
                type);

        // Send an async notification for the completed generations (will be used to add comments to Errata)
        notifyAdvisoryRelease(
                StandardAdvisoryReleaseEvent.builder()
                        .withRequestEventId(requestEvent.getId())
                        .withReleaseGenerations(releaseGenerations)
                        .build());

        return releaseGenerations.values();
    }

    private Set<String> getAllCPEsOfBuilds(Map<ProductVersionEntry, List<BuildItem>> buildDetails) {
        Set<String> allCPEs = new HashSet<>();
        buildDetails.forEach((productVersionEntry, buildItems) -> {
            // Map all VariantArch to ErrataVariant and collect distinct ErrataVariant objects
            Set<String> productVersionCPEs = buildItems.stream()
                    .flatMap(buildItem -> buildItem.getVariantArch().keySet().stream())
                    .map(variantArch -> errataClient.getVariant(variantArch))
                    .filter(Objects::nonNull)
                    .map(errataVariant -> errataVariant.getData().getAttributes().getCpe())
                    .filter(Objects::nonNull)
                    .collect(Collectors.toSet());
            allCPEs.addAll(productVersionCPEs);
        });
        return allCPEs;
    }

    @Transactional
    protected Collection<SbomGenerationRequest> createBuildManifestsForRPMBuilds(
            RequestEvent requestEvent,
            Details details,
            ErrataProduct product,
            Map<ProductVersionEntry, List<BuildItem>> buildDetails) {

        if (!featureFlags.standardErrataRPMManifestGenerationEnabled()) {
            return doIgnoreRequest(requestEvent, "Standard Errata RPM manifest generation is disabled");
        }

        log.debug("Creating build manifests for RPM builds: {}", buildDetails);

        Set<String> processedNvrs = new HashSet<>();
        Collection<SbomGenerationRequest> sbomRequests = new ArrayList<>();

        buildDetails.forEach((pVersion, items) -> {
            String productName = product.getData().getAttributes().getName();
            log.debug("Processing RPM builds of Errata Product '{}' with Product Version: '{}'", productName, pVersion);

            if (items == null || items.isEmpty()) {
                log.warn(
                        "No RPM builds associated with Errata {} and Product Version: '{}'",
                        details.getId(),
                        pVersion);
                return;
            }

            items.forEach(item -> {
                if (!processedNvrs.add(item.getNvr())) {
                    log.debug(
                            "Skipping duplicate NVR: '{}' because already being built for another Product Version",
                            item.getNvr());
                    return; // Already processed
                }

                BrewRPMConfig config = BrewRPMConfig.builder()
                        .withAdvisoryId(details.getId())
                        .withAdvisory(details.getFulladvisory())
                        .withBrewBuildId(item.getId())
                        .withBrewBuildNVR(item.getNvr())
                        .build();

                log.debug("Creating GenerationRequest Kubernetes resource...");

                GenerationRequest req = new GenerationRequestBuilder(GenerationRequestType.BREW_RPM)
                        .withIdentifier(config.getBrewBuildNVR())
                        .withStatus(SbomGenerationStatus.NEW)
                        .withConfig(config)
                        .build();

                log.debug("ConfigMap to create: '{}'", req);

                SbomGenerationRequest sbomGenerationRequest = SbomGenerationRequest.sync(requestEvent, req);

                sbomRequests.add(sbomGenerationRequest);
            });
        });

        return sbomRequests;
    }

    @Retry(maxRetries = 10, retryOn = KojiClientException.class)
    @BeforeRetry(RetryLogger.class)
    protected KojiClientSession getKojiSession() throws KojiClientException {
        if (kojiSession == null) {
            kojiSession = kojiSessionInstance.get();
        }
        return kojiSession;
    }

    protected void destroyKojiSession() {
        if (kojiSession != null) {
            kojiSessionInstance.destroy(kojiSession);
            kojiSession = null;
        }
    }

    private static final int BATCH_SIZE = 50;

    // This method will be retried up to 10 times if a KojiClientException is thrown
    @Retry(maxRetries = 10, retryOn = KojiClientException.class)
    @BeforeRetry(RetryLogger.class)
    protected Map<Long, String> getImageNamesFromBuilds(List<Long> buildIds) throws KojiClientException {
        KojiClientSession session = getKojiSession();
        List<CompletableFuture<Map<Long, String>>> futures = new ArrayList<>();

        for (int i = 0; i < buildIds.size(); i += BATCH_SIZE) {
            List<Long> batch = buildIds.subList(i, Math.min(i + BATCH_SIZE, buildIds.size()));
            futures.add(CompletableFuture.supplyAsync(() -> fetchImageNames(session, batch), managedExecutor));
        }

        Map<Long, String> merged = new HashMap<>();
        try {
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

            for (CompletableFuture<Map<Long, String>> future : futures) {
                merged.putAll(future.get());
            }
        } catch (InterruptedException | ExecutionException e) {
            log.error("Error while fetching image names for builds: {}", buildIds, e);
            destroyKojiSession();
            throw new KojiClientException("Batch processing failed", e);
        }

        return merged;
    }

    protected Map<Long, String> fetchImageNames(KojiClientSession session, List<Long> buildIds) {
        try {
            Map<Long, String> buildsToImageName = new HashMap<>();
            List<KojiIdOrName> ids = buildIds.stream().map(id -> new KojiIdOrName(id.intValue())).toList();

            List<KojiBuildInfo> buildInfos = session.getBuild(ids);

            for (KojiBuildInfo info : buildInfos) {
                Map<String, Object> extra = info.getExtra();
                if (extra == null) {
                    continue;
                }

                Object imageObj = extra.get("image");
                if (!(imageObj instanceof Map)) {
                    continue;
                }

                Map<String, Object> imageMap = (Map<String, Object>) imageObj;
                Object indexObj = imageMap.get("index");
                if (!(indexObj instanceof Map)) {
                    continue;
                }

                Map<String, Object> indexMap = (Map<String, Object>) indexObj;
                Object pullsObj = indexMap.get("pull");
                if (!(pullsObj instanceof List)) {
                    continue;
                }

                List<?> pulls = (List<?>) pullsObj;
                if (pulls.isEmpty()) {
                    continue;
                }

                String imageName = pulls.stream()
                        .filter(item -> item instanceof String && ((String) item).contains("sha256"))
                        .map(Object::toString)
                        .findFirst()
                        .orElse(pulls.get(0).toString());

                buildsToImageName.put((long) info.getId(), imageName);
            }

            return buildsToImageName;
        } catch (KojiClientException e) {
            log.error("Unable to fetch containers information for buildIDs (batch): {}", buildIds, e);
            destroyKojiSession();
            throw new RuntimeException(e);
        }
    }

    private void printAllErratumData(Errata erratum) {

        Optional<JsonNode> notes = erratum.getNotesMapping();

        if (notes.isEmpty()) {
            log.info("The erratum does not contain any JSON content inside the notes...");
        } else {
            log.info("The erratum contains a notes content with following JSON: \n{}", notes.get().toPrettyString());
        }

        if (erratum.getDetails().isEmpty()) {
            log.warn("Mmmmm I don't know how to get the release information...");
            return;
        }

        log.info("Fetching Erratum release ...");
        ErrataRelease erratumRelease = errataClient.getRelease(String.valueOf(erratum.getDetails().get().getGroupId()));

        log.info("Fetching Erratum builds list ...");
        ErrataBuildList erratumBuildList = errataClient
                .getBuildsList(String.valueOf(erratum.getDetails().get().getId()));

        StringBuilder summary = new StringBuilder("\n**********************************\n");
        summary.append("ID: ").append(erratum.getDetails().get().getId());
        summary.append("\nTYPE: ").append(erratum.getOriginalType());
        summary.append("\nAdvisory: ").append(erratum.getDetails().get().getFulladvisory());
        summary.append("\nSynopsis: ").append(erratum.getDetails().get().getSynopsis());
        summary.append("\nStatus: ").append(erratum.getDetails().get().getStatus());
        summary.append("\nCVE: ").append(erratum.getContent().getContent().getCve());
        summary.append("\n\nProduct: ")
                .append(erratum.getDetails().get().getProduct().getName())
                .append("(")
                .append(erratum.getDetails().get().getProduct().getShortName())
                .append(")");
        summary.append("\nRelease: ").append(erratumRelease.getData().getAttributes().getName());
        summary.append("\n\nBuilds: ");
        if (erratumBuildList != null && erratumBuildList.getProductVersions() != null
                && !erratumBuildList.getProductVersions().isEmpty()) {
            for (ProductVersionEntry productVersionEntry : erratumBuildList.getProductVersions().values()) {
                summary.append("\n\tProduct Version: ").append(productVersionEntry.getName());
                for (Build build : productVersionEntry.getBuilds()) {

                    summary.append("\n\t\t")
                            .append(
                                    build.getBuildItems()
                                            .values()
                                            .stream()
                                            .map(
                                                    buildItem -> "ID: " + buildItem.getId() + ", NVR: "
                                                            + buildItem.getNvr() + ", Variant: "
                                                            + buildItem.getVariantArch().keySet())
                                            .collect(Collectors.joining("\n\t\t")));
                }
            }
        }
        if (notes.isPresent()) {
            summary.append("\nJSON Notes:\n").append(notes.get().toPrettyString());
        } else {
            if (erratum.getContent().getContent().getNotes() != null
                    && !erratum.getContent().getContent().getNotes().trim().isEmpty()) {
                summary.append("\nNotes:\n").append(erratum.getContent().getContent().getNotes());
            }
        }

        summary.append("\n**********************************\n");
        System.out.println(summary); // NOSONAR: We want to use 'System.out' here
    }

}
