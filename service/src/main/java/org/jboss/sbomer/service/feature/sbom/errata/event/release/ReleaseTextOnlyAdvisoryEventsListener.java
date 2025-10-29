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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.component.evidence.Identity.Field;
import org.eclipse.microprofile.faulttolerance.Retry;
import org.jboss.sbomer.core.config.request.ErrataAdvisoryRequestConfig;
import org.jboss.sbomer.core.dto.v1beta1.V1Beta1RequestManifestRecord;
import org.jboss.sbomer.core.dto.v1beta1.V1Beta1RequestRecord;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.Constants;
import org.jboss.sbomer.core.features.sbom.enums.GenerationResult;
import org.jboss.sbomer.core.features.sbom.enums.RequestEventStatus;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.core.rest.faulttolerance.RetryLogger;
import org.jboss.sbomer.service.feature.sbom.errata.dto.Errata;
import org.jboss.sbomer.service.feature.sbom.errata.event.AdvisoryEventUtils;
import org.jboss.sbomer.service.feature.sbom.errata.event.util.MdcEventWrapper;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationStatus;
import org.jboss.sbomer.service.feature.sbom.model.RequestEvent;
import org.jboss.sbomer.service.feature.sbom.model.Sbom;
import org.jboss.sbomer.service.feature.sbom.model.SbomGenerationRequest;
import org.slf4j.MDC;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.quarkus.narayana.jta.QuarkusTransaction;
import io.smallrye.faulttolerance.api.BeforeRetry;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.ObservesAsync;
import lombok.extern.slf4j.Slf4j;

@ApplicationScoped
@Slf4j
public class ReleaseTextOnlyAdvisoryEventsListener extends AbstractEventsListener {

    public void onReleaseAdvisoryEvent(@ObservesAsync MdcEventWrapper wrapper) {
        Object payload = wrapper.getPayload();
        if (!(payload instanceof TextOnlyAdvisoryReleaseEvent event)) {
            return;
        }

        Map<String, String> mdcContext = wrapper.getMdcContext();
        if (mdcContext != null) {
            MDC.setContextMap(mdcContext);
        } else {
            MDC.clear();
        }

        log.debug("Event received for text-only advisory release ...");

        try {
            RequestEvent requestEvent = requestEventRepository.findById(event.getRequestEventId());
            try {
                ErrataAdvisoryRequestConfig config = (ErrataAdvisoryRequestConfig) requestEvent.getRequestConfig();
                Errata erratum = errataClient.getErratum(config.getAdvisoryId());
                String toolVersion = statsService.getStats().getVersion();
                // FIXME: 'Optional.get()' without 'isPresent()' check
                Component.Type productType = AdvisoryEventUtils
                        .getComponentTypeForProduct(erratum.getDetails().get().getProduct().getShortName());
                // FIXME:'Optional.get()' without 'isPresent()' check
                JsonNode notes = erratum.getNotesMapping().get();
                List<String> manifestsPurls;

                if (notes.has("manifest")) {
                    log.debug(
                            "Creating release manifests for manual builds of advisory: '{}'[{}]",
                            erratum.getDetails().get().getFulladvisory(),
                            erratum.getDetails().get().getId());

                    // If the notes contain a "manifest" field, search the successful generations for all the purls
                    // listed
                    // (there are no generations associated with the request event because no generations were
                    // triggered)
                    manifestsPurls = AdvisoryEventUtils.extractPurlUrisFromManifestNode(notes);
                } else {
                    log.debug(
                            "Creating release manifests for managed builds of advisory: '{}'[{}]",
                            erratum.getDetails().get().getFulladvisory(),
                            erratum.getDetails().get().getId());

                    // If the notes contain a "deliverables" field, search the latest successful generations triggered
                    // by
                    // the request event
                    V1Beta1RequestRecord advisoryManifestsRecord = sbomService
                            .searchLastSuccessfulAdvisoryBuildRequestRecord(
                                    requestEvent.getId(),
                                    config.getAdvisoryId());
                    manifestsPurls = advisoryManifestsRecord.manifests()
                            .stream()
                            .map(V1Beta1RequestManifestRecord::rootPurl)
                            .toList();
                }

                List<Sbom> sboms = findSbomsByPurls(manifestsPurls);
                if (sboms.isEmpty()) {
                    markRequestFailed(
                            requestEvent,
                            event.getReleaseGenerations().values(),
                            "There are no matching sboms for the content specified within the advisory notes.");
                    doUpdateGenerationsStatus(event.getReleaseGenerations().values());
                    return;
                }
                createReleaseManifestsForTextOnlyAdvisories(
                        requestEvent,
                        erratum,
                        sboms,
                        event.getReleaseGenerations(),
                        toolVersion,
                        productType);
            } catch (Exception e) {
                log.error(
                        "An error occurred during the creation of release manifests for event '{}'",
                        requestEvent.getId(),
                        e);
                markRequestFailed(
                        requestEvent,
                        event.getReleaseGenerations().values(),
                        "An error occurred during the creation of the release manifest");
            }

            // Let's trigger the update of statuses and advisory comments
            doUpdateGenerationsStatus(event.getReleaseGenerations().values());
        } finally {
            MDC.clear();
        }
    }

    private List<Sbom> findSbomsByPurls(List<String> purls) {
        if (purls == null || purls.isEmpty()) {
            return Collections.emptyList();
        }
        return purls.stream().map(sbomService::findByPurl).filter(Objects::nonNull).toList();
    }

    protected void createReleaseManifestsForTextOnlyAdvisories(
            RequestEvent requestEvent,
            Errata erratum,
            List<Sbom> sboms,
            Map<String, SbomGenerationRequest> releaseGenerations,
            String toolVersion,
            Component.Type productType) {
        // FIXME: 'Optional.get()' without 'isPresent()' check
        String productName = erratum.getDetails().get().getProduct().getName();
        String productVersion = erratum.getContent().getContent().getProductVersionText();
        String cpeText = erratum.getContent().getContent().getTextOnlyCpe();

        // Create the release manifest for this ProductVersion
        Bom productVersionBom = createProductVersionBom(productType, erratum, toolVersion);
        for (Sbom sbom : sboms) {
            Component sbomRootComponent = createRootComponentForSbom(sbom);
            // Add the component to the release manifest components and add the purl to the "provides" list
            productVersionBom.addComponent(sbomRootComponent);
            productVersionBom.getDependencies().get(0).addProvides(new Dependency(sbomRootComponent.getPurl()));
        }

        // Add the AdvisoryId property
        SbomUtils.addPropertyIfMissing(
                productVersionBom.getMetadata(),
                Constants.CONTAINER_PROPERTY_ADVISORY_ID,
                String.valueOf(erratum.getDetails().get().getId()));

        SbomUtils.addMissingMetadataSupplier(productVersionBom);
        SbomUtils.addMissingSerialNumber(productVersionBom);

        SbomGenerationRequest releaseGeneration = releaseGenerations.get(cpeText);
        List<Sbom> sbomsToUpload = saveReleaseManifestForTextOnlyAdvisories(
                requestEvent,
                erratum,
                productName,
                productVersion,
                toolVersion,
                releaseGeneration,
                productVersionBom,
                sboms);

        log.info(
                "Saved and modified SBOM '{}' for generation '{}' for ProductVersion '{}' of errata '{}'",
                sbomsToUpload.get(sbomsToUpload.size() - 1), // Will always be release SBOM
                releaseGeneration.getId(),
                productVersion,
                erratum.getDetails().get().getFulladvisory());

        performPost(sbomsToUpload);
    }

    // FIXME: 'Optional.get()' without 'isPresent()' check
    private Bom createProductVersionBom(Component.Type productType, Errata erratum, String toolVersion) {
        String productName = erratum.getDetails().get().getProduct().getName();
        String productVersion = erratum.getContent().getContent().getProductVersionText();
        String cpe = erratum.getContent().getContent().getTextOnlyCpe();

        // Create the release manifest for this ProductVersion
        Bom bom = SbomUtils.createBom();
        // FIXME: This method can return null
        Objects.requireNonNull(bom);
        Metadata metadata = createMetadata(
                productName,
                productVersion,
                productType,
                Set.of(cpe),
                erratum.getDetails().get().getActualShipDate() != null
                        ? Date.from(erratum.getDetails().get().getActualShipDate())
                        : null,
                toolVersion);
        bom.setMetadata(metadata);
        Dependency mainDependency = new Dependency(metadata.getComponent().getBomRef());
        bom.setDependencies(List.of(mainDependency));
        return bom;
    }

    protected Component createRootComponentForSbom(Sbom sbom) {

        Bom manifestBom = SbomUtils.fromJsonNode(sbom.getSbom());
        Component manifestMainComponent;
        Component metadataComponent = manifestBom.getMetadata().getComponent();
        // If there are no components get the main component from the metadata
        if (!SbomUtils.isNotEmpty(manifestBom.getComponents())) {
            manifestMainComponent = metadataComponent;
        } else {
            manifestMainComponent = manifestBom.getComponents().get(0);
        }
        String evidencePurl = SbomUtils.addQualifiersToPurlOfComponent(
                manifestMainComponent,
                Map.of("repository_url", Constants.MRRC_URL),
                !SbomUtils.hasProperty(manifestMainComponent, Constants.SBOM_RED_HAT_DELIVERABLE_URL));

        // Finally, create the root component for this build (NVR) from the manifest
        Component sbomRootComponent = SbomUtils.createComponent(manifestMainComponent);

        sbomRootComponent.setSupplier(manifestMainComponent.getSupplier());
        sbomRootComponent.setPublisher(manifestMainComponent.getPublisher());
        sbomRootComponent.setHashes(manifestMainComponent.getHashes());
        sbomRootComponent.setLicenses(manifestMainComponent.getLicenses());
        SbomUtils.setEvidenceIdentities(sbomRootComponent, Set.of(evidencePurl), Field.PURL);

        // Try and aquire the version from the purl(s)
        SbomUtils.setPurlVersionFromGeneric(sbomRootComponent);

        return sbomRootComponent;
    }

    // Add a very long timeout because this method could potentially need to update hundreds of manifests
    @Retry(maxRetries = 10)
    @BeforeRetry(RetryLogger.class)
    protected List<Sbom> saveReleaseManifestForTextOnlyAdvisories(
            RequestEvent requestEvent,
            Errata erratum,
            String productName,
            String productVersion,
            String toolVersion,
            SbomGenerationRequest releaseGeneration,
            Bom productVersionBom,
            List<Sbom> sboms) {

        try {
            List<Sbom> sbomsToUpload = new ArrayList<>();
            QuarkusTransaction.begin(QuarkusTransaction.beginOptions().timeout(INCREASED_TIMEOUT_SEC));

            // 1 - Save the release generation with the release manifest
            releaseGeneration = generationRequestRepository.findById(releaseGeneration.getId());
            releaseGeneration.setStatus(SbomGenerationStatus.FINISHED);
            releaseGeneration.setResult(GenerationResult.SUCCESS);

            // 1.1 - Create the Sbom entity
            Sbom releaseSbom = Sbom.builder()
                    .withIdentifier(releaseGeneration.getIdentifier())
                    .withSbom(SbomUtils.toJsonNode(productVersionBom))
                    .withGenerationRequest(releaseGeneration)
                    .withConfigIndex(0)
                    .build();

            // Add more information for this release so to find manifests more easily
            ObjectNode metadataNode = collectReleaseInfo(
                    requestEvent.getId(),
                    erratum,
                    productName,
                    productVersion,
                    productVersionBom);
            releaseSbom.setReleaseMetadata(metadataNode);
            releaseSbom = sbomService.save(releaseSbom);

            // 2 - For every sbom update it with the release repo
            log.debug("Processing {} sboms...", sboms.size());
            for (Sbom sbom : sboms) {
                log.debug("Updating sbom {} for release event {}...", sbom.getId(), requestEvent.getId());

                Sbom buildManifest = sbomService.get(sbom.getId());
                Bom manifestBom = SbomUtils.fromJsonNode(buildManifest.getSbom());
                SbomUtils.addMissingMetadataSupplier(manifestBom);

                // Add the AdvisoryId property
                SbomUtils.addPropertyIfMissing(
                        manifestBom.getMetadata(),
                        Constants.CONTAINER_PROPERTY_ADVISORY_ID,
                        String.valueOf(erratum.getDetails().get().getId()));

                Component metadataComponent = manifestBom.getMetadata() != null
                        ? manifestBom.getMetadata().getComponent()
                        : null;
                if (metadataComponent != null) {
                    adjustComponent(metadataComponent);
                }
                for (Component component : manifestBom.getComponents()) {
                    adjustComponent(component);
                }

                // 2.7 - Update the original Sbom
                buildManifest.setSbom(SbomUtils.toJsonNode(manifestBom));

                // 2.8 - Add more information for this release so to find manifests more easily
                ObjectNode buildManifestMetadataNode = collectReleaseInfo(
                        requestEvent.getId(),
                        erratum,
                        productName,
                        productVersion,
                        manifestBom);
                buildManifest.setReleaseMetadata(buildManifestMetadataNode);
                sbomsToUpload.add(buildManifest);
            }

            requestEvent = requestEventRepository.findById(requestEvent.getId());
            requestEvent.setEventStatus(RequestEventStatus.SUCCESS);
            QuarkusTransaction.commit();
            sbomsToUpload.add(releaseSbom); // For consistency upload release after build SBOMs

            return sbomsToUpload;
        } catch (Exception e) {
            try {
                QuarkusTransaction.rollback();
            } catch (Exception rollbackException) {
                log.error("Transaction was rolled back!!", rollbackException);
            }
            throw new ApplicationException(
                    "Could not save the release and build manifests for release generation {}",
                    releaseGeneration.getIdentifier(),
                    e);
        }
    }

    // FIXME: 'Optional.get()' without 'isPresent()' check
    protected ObjectNode collectReleaseInfo(
            String requestEventId,
            Errata erratum,
            String product,
            String productVersion,
            Bom manifest) {
        ObjectNode releaseMetadata = ObjectMapperProvider.json().createObjectNode();
        releaseMetadata.put(REQUEST_ID, requestEventId);
        releaseMetadata.put(ERRATA, erratum.getDetails().get().getFulladvisory());
        releaseMetadata.put(ERRATA_ID, erratum.getDetails().get().getId());
        if (erratum.getDetails().get().getActualShipDate() != null) {
            releaseMetadata.put(ERRATA_SHIP_DATE, Date.from(erratum.getDetails().get().getActualShipDate()).toString());
        }
        releaseMetadata.put(PRODUCT, product);
        releaseMetadata.put(PRODUCT_SHORTNAME, erratum.getDetails().get().getProduct().getShortName());
        releaseMetadata.put(PRODUCT_VERSION, productVersion);

        TreeSet<String> allPurls = new TreeSet<>();
        if (manifest.getMetadata() != null) {
            allPurls.addAll(SbomUtils.getAllPurlsOfComponent(manifest.getMetadata().getComponent()));
        }
        for (Component component : manifest.getComponents()) {
            allPurls.addAll(SbomUtils.getAllPurlsOfComponent(component));
        }
        ArrayNode purlArray = ObjectMapperProvider.json().createArrayNode();
        for (String purl : allPurls) {
            purlArray.add(purl);
        }
        releaseMetadata.set(PURL_LIST, purlArray);
        return releaseMetadata;
    }

    protected void adjustComponent(Component component) {

        String evidencePurl = SbomUtils.addQualifiersToPurlOfComponent(
                component,
                Map.of("repository_url", Constants.MRRC_URL),
                SbomUtils.hasProperty(component, Constants.SBOM_RED_HAT_DELIVERABLE_URL));
        log.debug("Calculated evidence purl: {}", evidencePurl);
        component.setPurl(evidencePurl);
        SbomUtils.setEvidenceIdentities(component, Set.of(evidencePurl), Field.PURL);
    }

}
