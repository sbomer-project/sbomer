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

import static org.jboss.sbomer.service.feature.sbom.pyxis.PyxisClient.REPOSITORIES_DETAILS_INCLUDES;
import static org.jboss.sbomer.service.feature.sbom.pyxis.PyxisClient.REPOSITORIES_REGISTRY_INCLUDES;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.component.evidence.Identity.Field;
import org.eclipse.microprofile.faulttolerance.Retry;
import org.jboss.sbomer.core.config.request.ErrataAdvisoryRequestConfig;
import org.jboss.sbomer.core.dto.v1beta1.V1Beta1GenerationRecord;
import org.jboss.sbomer.core.dto.v1beta1.V1Beta1RequestManifestRecord;
import org.jboss.sbomer.core.dto.v1beta1.V1Beta1RequestRecord;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.Constants;
import org.jboss.sbomer.core.features.sbom.enums.GenerationRequestType;
import org.jboss.sbomer.core.features.sbom.enums.GenerationResult;
import org.jboss.sbomer.core.features.sbom.enums.RequestEventStatus;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.core.rest.faulttolerance.RetryLogger;
import org.jboss.sbomer.service.feature.sbom.errata.dto.Errata;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataBuildList;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataBuildList.BuildItem;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataBuildList.ProductVersionEntry;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataCDNRepoNormalized;
import org.jboss.sbomer.service.feature.sbom.errata.event.AdvisoryEventUtils;
import org.jboss.sbomer.service.feature.sbom.errata.event.util.MdcEventWrapper;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationStatus;
import org.jboss.sbomer.service.feature.sbom.model.RequestEvent;
import org.jboss.sbomer.service.feature.sbom.model.Sbom;
import org.jboss.sbomer.service.feature.sbom.model.SbomGenerationRequest;
import org.jboss.sbomer.service.feature.sbom.pyxis.PyxisValidatingClient;
import org.jboss.sbomer.service.feature.sbom.pyxis.dto.PyxisRepository;
import org.jboss.sbomer.service.feature.sbom.pyxis.dto.PyxisRepositoryDetails;
import org.jboss.sbomer.service.feature.sbom.pyxis.dto.RepositoryCoordinates;
import org.slf4j.MDC;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

import io.quarkus.narayana.jta.QuarkusTransaction;
import io.smallrye.faulttolerance.api.BeforeRetry;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.ObservesAsync;
import jakarta.inject.Inject;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@ApplicationScoped
@Slf4j
public class ReleaseStandardAdvisoryEventsListener extends AbstractEventsListener {

    @Inject
    @Setter
    PyxisValidatingClient pyxisClient;

    private static final String NVR_STANDARD_SEPARATOR = "-";

    public void onReleaseAdvisoryEvent(@ObservesAsync MdcEventWrapper wrapper) {
        Object payload = wrapper.getPayload();
        if (!(payload instanceof StandardAdvisoryReleaseEvent event)) {
            return;
        }

        Map<String, String> mdcContext = wrapper.getMdcContext();
        if (mdcContext != null) {
            MDC.setContextMap(mdcContext);
        } else {
            MDC.clear();
        }

        log.debug("Event received for standard advisory release ...");

        try {
            RequestEvent requestEvent = requestEventRepository.findById(event.getRequestEventId());
            try {
                ErrataAdvisoryRequestConfig config = (ErrataAdvisoryRequestConfig) requestEvent.getRequestConfig();
                Errata erratum = errataClient.getErratum(config.getAdvisoryId());
                Map<ProductVersionEntry, List<BuildItem>> advisoryBuildDetails = getAdvisoryBuildDetails(
                        config.getAdvisoryId());
                V1Beta1RequestRecord advisoryManifestsRecord = sbomService
                        .searchLastSuccessfulAdvisoryBuildRequestRecord(requestEvent.getId(), config.getAdvisoryId());

                String toolVersion = statsService.getStats().getVersion();
                // FIXME: 'Optional.get()' without 'isPresent()' check
                Component.Type productType = AdvisoryEventUtils
                        .getComponentTypeForProduct(erratum.getDetails().get().getProduct().getShortName());

                // Associate each ProductVersion with its list of CPEs
                Map<ProductVersionEntry, Set<String>> productVersionToCPEs = mapProductVersionToCPEs(
                        advisoryBuildDetails);

                // Associate each build (NVR) in an advisory to its build manifest generation
                Map<String, V1Beta1GenerationRecord> nvrToBuildGeneration = mapNVRToBuildGeneration(
                        advisoryManifestsRecord);

                if (erratum.getDetails().get().getContentTypes().contains("docker")) {
                    log.debug(
                            "Creating release manifests for Docker builds of advisory: '{}'[{}]",
                            erratum.getDetails().get().getFulladvisory(),
                            erratum.getDetails().get().getId());
                    releaseManifestsForDockerBuilds(
                            requestEvent,
                            erratum,
                            advisoryBuildDetails,
                            advisoryManifestsRecord,
                            event.getReleaseGenerations(),
                            toolVersion,
                            productType,
                            productVersionToCPEs,
                            nvrToBuildGeneration);

                } else if (erratum.getDetails().get().getContentTypes().contains("rpm")
                        || erratum.getDetails().get().getContentTypes().contains("module")) {
                    log.debug(
                            "Creating release manifests for RPM builds of advisory: '{}'[{}]",
                            erratum.getDetails().get().getFulladvisory(),
                            erratum.getDetails().get().getId());
                    releaseManifestsForRPMBuilds(
                            requestEvent,
                            erratum,
                            advisoryBuildDetails,
                            advisoryManifestsRecord,
                            event.getReleaseGenerations(),
                            toolVersion,
                            productType,
                            productVersionToCPEs,
                            nvrToBuildGeneration);

                } else {
                    log.warn(
                            "Unhandled content-types ({}) of advisory: '{}'[{}]",
                            erratum.getDetails().get().getContentTypes(),
                            erratum.getDetails().get().getFulladvisory(),
                            erratum.getDetails().get().getId());
                }
            } catch (Exception e) {
                log.error(
                        "An error occurred during the creation of release manifests for event '{}'",
                        requestEvent.getId(),
                        e);
                String reason = (e instanceof ApplicationException) ? e.getMessage()
                        : "An error occurred during the creation of the release manifest";
                markRequestFailed(requestEvent, event.getReleaseGenerations().values(), reason);
            }

            // Let's trigger the update of statuses and advisory comments
            doUpdateGenerationsStatus(event.getReleaseGenerations().values());
        } finally {
            MDC.clear();
        }
    }

    protected void releaseManifestsForRPMBuilds(
            RequestEvent requestEvent,
            Errata erratum,
            Map<ProductVersionEntry, List<BuildItem>> advisoryBuildDetails,
            V1Beta1RequestRecord advisoryManifestsRecord,
            Map<String, SbomGenerationRequest> releaseGenerations,
            String toolVersion,
            Component.Type productType,
            Map<ProductVersionEntry, Set<String>> productVersionToCPEs,
            Map<String, V1Beta1GenerationRecord> nvrToBuildGeneration) {

        advisoryBuildDetails.forEach((productVersion, buildItems) -> {

            // Create the release manifest for this ProductVersion
            Bom productVersionBom = createProductVersionBom(
                    productVersion,
                    productType,
                    productVersionToCPEs,
                    erratum,
                    toolVersion);

            Map<String, List<ErrataCDNRepoNormalized>> generationToCDNs = new HashMap<>();

            for (BuildItem buildItem : buildItems) {
                V1Beta1GenerationRecord buildGeneration = nvrToBuildGeneration.get(buildItem.getNvr());
                if (buildGeneration != null) {
                    // It could happen that not all the builds attached to the advisory have a generation done in SBOMer
                    // (the builds which SBOMer is not able to manifest)
                    // FIXME: 'Optional.get()' without 'isPresent()' check
                    Component nvrRootComponent = createRootComponentForRPMBuildItem(
                            buildItem,
                            buildGeneration,
                            advisoryManifestsRecord,
                            erratum.getDetails().get().getProduct().getShortName(),
                            generationToCDNs);

                    // Add the component to the release manifest components and add the purl to the "provides" list
                    productVersionBom.addComponent(nvrRootComponent);
                    productVersionBom.getDependencies().get(0).addProvides(new Dependency(nvrRootComponent.getPurl()));
                }
            }

            // Add the AdvisoryId property
            SbomUtils.addPropertyIfMissing(
                    productVersionBom.getMetadata(),
                    Constants.CONTAINER_PROPERTY_ADVISORY_ID,
                    String.valueOf(erratum.getDetails().get().getId()));

            SbomUtils.addMissingMetadataSupplier(productVersionBom);
            SbomUtils.addMissingSerialNumber(productVersionBom);

            SbomGenerationRequest releaseGeneration = releaseGenerations.get(productVersion.getName());
            List<Sbom> sboms = saveReleaseManifestForRPMGeneration(
                    requestEvent,
                    erratum,
                    productVersion,
                    toolVersion,
                    releaseGeneration,
                    productVersionBom,
                    advisoryManifestsRecord,
                    generationToCDNs);
            // FIXME: 'Optional.get()' without 'isPresent()' check
            log.info(
                    "Saved and modified SBOM '{}' for generation '{}' for ProductVersion '{}' of errata '{}' for RPM builds",
                    sboms.get(sboms.size() - 1), // Will always be release SBOM
                    releaseGeneration.getId(),
                    productVersion.getName(),
                    erratum.getDetails().get().getFulladvisory());

            performPost(sboms);
        });
    }

    protected void releaseManifestsForDockerBuilds(
            RequestEvent requestEvent,
            Errata erratum,
            Map<ProductVersionEntry, List<BuildItem>> advisoryBuildDetails,
            V1Beta1RequestRecord advisoryManifestsRecord,
            Map<String, SbomGenerationRequest> releaseGenerations,
            String toolVersion,
            Component.Type productType,
            Map<ProductVersionEntry, Set<String>> productVersionToCPEs,
            Map<String, V1Beta1GenerationRecord> nvrToBuildGeneration) {

        advisoryBuildDetails.forEach((productVersion, buildItems) -> {

            // Create the release manifest for this ProductVersion
            Bom productVersionBom = createProductVersionBom(
                    productVersion,
                    productType,
                    productVersionToCPEs,
                    erratum,
                    toolVersion);

            // Associate each build (NVR == generation) in an advisory to the repositories where it is published to
            Map<String, List<RepositoryCoordinates>> generationToRepositories = new HashMap<>();

            for (BuildItem buildItem : buildItems) {
                V1Beta1GenerationRecord buildGeneration = nvrToBuildGeneration.get(buildItem.getNvr());
                if (buildGeneration != null) {
                    // It could happen that not all the builds attached to the advisory have a generation done in SBOMer
                    // (the builds which SBOMer is not able to manifest like build#3572808)
                    Component nvrRootComponent = createRootComponentForDockerBuildItem(
                            buildItem.getNvr(),
                            buildGeneration,
                            advisoryManifestsRecord,
                            generationToRepositories);

                    // Add the component to the release manifest components and add the purl to the "provides" list
                    productVersionBom.addComponent(nvrRootComponent);
                    productVersionBom.getDependencies().get(0).addProvides(new Dependency(nvrRootComponent.getPurl()));
                }
            }

            // Add the AdvisoryId property
            SbomUtils.addPropertyIfMissing(
                    productVersionBom.getMetadata(),
                    Constants.CONTAINER_PROPERTY_ADVISORY_ID,
                    String.valueOf(erratum.getDetails().get().getId()));

            SbomUtils.addMissingMetadataSupplier(productVersionBom);
            SbomUtils.addMissingSerialNumber(productVersionBom);

            SbomGenerationRequest releaseGeneration = releaseGenerations.get(productVersion.getName());
            List<Sbom> sboms = saveReleaseManifestForDockerGeneration(
                    requestEvent,
                    erratum,
                    productVersion,
                    toolVersion,
                    releaseGeneration,
                    productVersionBom,
                    advisoryManifestsRecord,
                    generationToRepositories);
            // FIXME: 'Optional.get()' without 'isPresent()' check
            log.info(
                    "Saved and modified SBOM '{}' for generation '{}' for ProductVersion '{}' of errata '{}' for Docker builds",
                    sboms.get(sboms.size() - 1), // Will always be release SBOM
                    releaseGeneration.getId(),
                    productVersion.getName(),
                    erratum.getDetails().get().getFulladvisory());

            performPost(sboms);
        });
    }

    private Bom createProductVersionBom(
            ProductVersionEntry productVersion,
            Component.Type productType,
            Map<ProductVersionEntry, Set<String>> productVersionToCPEs,
            Errata erratum,
            String toolVersion) {

        // Create the release manifest for this ProductVersion
        Bom productVersionBom = SbomUtils.createBom();
        // FIXME: This method can return null
        Objects.requireNonNull(productVersionBom);
        // FIXME: 'Optional.get()' without 'isPresent()' check
        Metadata productVersionMetadata = createMetadata(
                productVersion.getDescription(),
                productVersion.getName(),
                productType,
                productVersionToCPEs.get(productVersion),
                erratum.getDetails().get().getActualShipDate() != null
                        ? Date.from(erratum.getDetails().get().getActualShipDate())
                        : null,
                toolVersion);
        productVersionBom.setMetadata(productVersionMetadata);
        Dependency productVersionDependency = new Dependency(productVersionMetadata.getComponent().getBomRef());
        productVersionBom.setDependencies(List.of(productVersionDependency));
        return productVersionBom;
    }

    protected Component createRootComponentForRPMBuildItem(
            BuildItem buildItem,
            V1Beta1GenerationRecord generation,
            V1Beta1RequestRecord advisoryManifestsRecord,
            String productShortName,
            Map<String, List<ErrataCDNRepoNormalized>> generationToCDNs) {

        // From the generation triggered from this build (NVR), find the single manifest created and get the manifest
        // content that we need to copy the main component
        V1Beta1RequestManifestRecord manifestRecord = advisoryManifestsRecord.manifests()
                .stream()
                .filter(manifest -> manifest.generation().id().equals(generation.id()))
                .findFirst()
                .orElseThrow(
                        () -> new ApplicationException(
                                "Main manifest not found for generation '{}'",
                                generation.identifier()));

        Sbom manifestSbom = sbomService.get(manifestRecord.id());
        Bom manifestBom = SbomUtils.fromJsonNode(manifestSbom.getSbom());
        Component manifestMainComponent = manifestBom.getComponents().get(0);

        List<ErrataCDNRepoNormalized> allCDNs = getCDNDetails(buildItem, productShortName);
        generationToCDNs.put(generation.id(), allCDNs);

        // From the manifest get all the archs from the purl 'arch' qualifier
        Set<String> manifestArches = getAllArchitectures(manifestBom);
        Set<String> evidencePurls = AdvisoryEventUtils
                .createPurls(manifestMainComponent.getPurl(), allCDNs, manifestArches);

        // Finally, create the root component for this build (NVR) from the manifest
        Component nvrRootComponent = SbomUtils.createComponent(
                null,
                manifestMainComponent.getName(),
                manifestMainComponent.getVersion(),
                null,
                manifestMainComponent.getPurl(),
                manifestMainComponent.getType());

        nvrRootComponent.setSupplier(manifestMainComponent.getSupplier());
        nvrRootComponent.setPublisher(manifestMainComponent.getPublisher());
        nvrRootComponent.setHashes(manifestMainComponent.getHashes());
        nvrRootComponent.setLicenses(manifestMainComponent.getLicenses());
        SbomUtils.setEvidenceIdentities(nvrRootComponent, evidencePurls, Field.PURL);

        return nvrRootComponent;
    }

    protected Component createRootComponentForDockerBuildItem(
            String generationNVR,
            V1Beta1GenerationRecord generation,
            V1Beta1RequestRecord advisoryManifestsRecord,
            Map<String, List<RepositoryCoordinates>> generationToRepositories) {

        // From the generation triggered from this build (NVR), find the image-index manifest and get the manifest
        // content that we need to copy the main component
        V1Beta1RequestManifestRecord imageIndexManifest = findImageIndexManifest(advisoryManifestsRecord, generation);
        Sbom imageIndexSbom = sbomService.get(imageIndexManifest.id());
        Component imageIndexMainComponent = SbomUtils.fromJsonNode(imageIndexSbom.getSbom()).getComponents().get(0);

        // Find where this build (NVR) has been published to
        List<RepositoryCoordinates> repositories = getRepositoriesDetails(generationNVR);
        generationToRepositories.put(generation.id(), repositories);

        // Create summary (pick the longest value) and evidence purl
        Optional<RepositoryCoordinates> preferredRepo = AdvisoryEventUtils.findPreferredRepo(repositories);
        if (preferredRepo.isEmpty()) {
            throw new ApplicationException("No published repositories found in Pyxis for nvr '{}'", generationNVR);
        }

        String summaryPurl = AdvisoryEventUtils
                .createPurl(preferredRepo.get(), imageIndexMainComponent.getVersion(), false);
        Set<String> evidencePurls = AdvisoryEventUtils
                .createPurls(repositories, imageIndexMainComponent.getVersion(), true);

        // Finally, create the root component for this build (NVR) from the image index manifest
        Component nvrRootComponent = SbomUtils.createComponent(
                null,
                imageIndexMainComponent.getName(),
                imageIndexMainComponent.getVersion(),
                null,
                summaryPurl,
                imageIndexMainComponent.getType());

        nvrRootComponent.setSupplier(imageIndexMainComponent.getSupplier());
        nvrRootComponent.setPublisher(imageIndexMainComponent.getPublisher());
        nvrRootComponent.setHashes(imageIndexMainComponent.getHashes());
        nvrRootComponent.setLicenses(imageIndexMainComponent.getLicenses());
        SbomUtils.setEvidenceIdentities(nvrRootComponent, evidencePurls, Field.PURL);

        return nvrRootComponent;
    }

    // Add a very long timeout because this method could potentially need to update hundreds of manifests
    @Retry(maxRetries = 10)
    @BeforeRetry(RetryLogger.class)
    protected List<Sbom> saveReleaseManifestForRPMGeneration(
            RequestEvent requestEvent,
            Errata erratum,
            ProductVersionEntry productVersion,
            String toolVersion,
            SbomGenerationRequest releaseGeneration,
            Bom productVersionBom,
            V1Beta1RequestRecord advisoryManifestsRecord,
            Map<String, List<ErrataCDNRepoNormalized>> generationToCDNs) {

        try {
            List<Sbom> sboms = new ArrayList<>();
            QuarkusTransaction.begin(QuarkusTransaction.beginOptions().timeout(INCREASED_TIMEOUT_SEC));

            // 1 - Save the release generation with the release manifest
            releaseGeneration = generationRequestRepository.findById(releaseGeneration.getId());
            releaseGeneration.setStatus(SbomGenerationStatus.FINISHED);
            releaseGeneration.setResult(GenerationResult.SUCCESS);

            // 1.1 - Create the Sbom entity
            Sbom sbom = Sbom.builder()
                    .withIdentifier(releaseGeneration.getIdentifier())
                    .withSbom(SbomUtils.toJsonNode(productVersionBom))
                    .withGenerationRequest(releaseGeneration)
                    .withConfigIndex(0)
                    .build();

            // Add more information for this release so to find manifests more easily
            ObjectNode metadataNode = collectReleaseInfo(
                    requestEvent.getId(),
                    erratum,
                    productVersion,
                    productVersionBom);
            sbom.setReleaseMetadata(metadataNode);
            sbom = sbomService.save(sbom);

            // 2 - For every generation, find all the existing manifests and update them with release repo
            // data
            log.debug("Processing {} generations for RPMs...", generationToCDNs.size());
            for (Map.Entry<String, List<ErrataCDNRepoNormalized>> entry : generationToCDNs.entrySet()) {
                String generationId = entry.getKey();
                // 2.1 Get all the CDNs associated with this request
                List<ErrataCDNRepoNormalized> generationCDNs = entry.getValue();

                // 2.2 - For every manifest previously generated from this generation
                Collection<V1Beta1RequestManifestRecord> buildManifests = advisoryManifestsRecord.manifests()
                        .stream()
                        .filter(manifest -> manifest.generation().id().equals(generationId))
                        .toList();

                for (V1Beta1RequestManifestRecord buildManifestRecord : buildManifests) {
                    log.debug(
                            "Updating build manifest '{}' for release event {}...",
                            buildManifestRecord.id(),
                            requestEvent.getId());

                    Sbom buildManifest = sbomService.get(buildManifestRecord.id());
                    Bom manifestBom = SbomUtils.fromJsonNode(buildManifest.getSbom());
                    SbomUtils.addMissingMetadataSupplier(manifestBom);

                    // Add the AdvisoryId property
                    SbomUtils.addPropertyIfMissing(
                            manifestBom.getMetadata(),
                            Constants.CONTAINER_PROPERTY_ADVISORY_ID,
                            String.valueOf(erratum.getDetails().get().getId()));

                    // For each component, I need to find the matching CDNs repo, selecting the longest one to update
                    // the purl.
                    // And getting them all to create the evidence
                    Set<String> manifestArches = getAllArchitectures(manifestBom);
                    log.debug("Archs detected in the manifest: {}", manifestArches);

                    Component metadataComponent = manifestBom.getMetadata() != null
                            ? manifestBom.getMetadata().getComponent()
                            : null;
                    if (metadataComponent != null) {
                        adjustComponent(metadataComponent, generationCDNs, manifestArches);
                    }
                    for (Component component : manifestBom.getComponents()) {
                        adjustComponent(component, generationCDNs, manifestArches);
                    }

                    // 2.7 - Update the original Sbom
                    buildManifest.setSbom(SbomUtils.toJsonNode(manifestBom));

                    // 2.8 - Add more information for this release so to find manifests more easily
                    ObjectNode buildManifestMetadataNode = collectReleaseInfo(
                            requestEvent.getId(),
                            erratum,
                            productVersion,
                            manifestBom);
                    buildManifest.setReleaseMetadata(buildManifestMetadataNode);
                    sboms.add(buildManifest);
                }
            }

            requestEvent = requestEventRepository.findById(requestEvent.getId());
            requestEvent.setEventStatus(RequestEventStatus.SUCCESS);
            QuarkusTransaction.commit();
            sboms.add(sbom); // For consistency upload release after build SBOMs

            return sboms;
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

    // TODO: Refactor
    // Add a very long timeout because this method could potentially need to update hundreds of manifests
    @Retry(maxRetries = 10)
    @BeforeRetry(RetryLogger.class)
    protected List<Sbom> saveReleaseManifestForDockerGeneration(
            RequestEvent requestEvent,
            Errata erratum,
            ProductVersionEntry productVersion,
            String toolVersion,
            SbomGenerationRequest releaseGeneration,
            Bom productVersionBom,
            V1Beta1RequestRecord advisoryManifestsRecord,
            Map<String, List<RepositoryCoordinates>> generationToRepositories) {

        try {
            List<Sbom> sboms = new ArrayList<>();
            QuarkusTransaction.begin(QuarkusTransaction.beginOptions().timeout(INCREASED_TIMEOUT_SEC));

            // 1 - Save the release generation with the release manifest
            releaseGeneration = generationRequestRepository.findById(releaseGeneration.getId());
            releaseGeneration.setStatus(SbomGenerationStatus.FINISHED);
            releaseGeneration.setResult(GenerationResult.SUCCESS);

            // 1.1 - Create the Sbom entity
            Sbom sbom = Sbom.builder()
                    .withIdentifier(releaseGeneration.getIdentifier())
                    .withSbom(SbomUtils.toJsonNode(productVersionBom))
                    .withGenerationRequest(releaseGeneration)
                    .withConfigIndex(0)
                    .build();

            // Add more information for this release so to find manifests more easily
            ObjectNode metadataNode = collectReleaseInfo(
                    requestEvent.getId(),
                    erratum,
                    productVersion,
                    productVersionBom);
            sbom.setReleaseMetadata(metadataNode);
            sbom = sbomService.save(sbom);

            // 2 - For every generation, find all the existing manifests and update them with release repo
            // data
            log.debug("Processing {} generations for Docker...", generationToRepositories.size());
            for (Map.Entry<String, List<RepositoryCoordinates>> entry : generationToRepositories.entrySet()) {
                String generationId = entry.getKey();
                // 2.1 - Select the repository with longest repoFragment + tag
                List<RepositoryCoordinates> repositories = entry.getValue();
                Optional<RepositoryCoordinates> preferredRepo = AdvisoryEventUtils.findPreferredRepo(repositories);
                if (preferredRepo.isEmpty()) {
                    throw new ApplicationException("No published repositories found in Pyxis");
                }

                // 2.2 - Regenerate the manifest purls using the preferredRepo and keep track of the updates.
                // We need them to update the index manifest variants
                Collection<V1Beta1RequestManifestRecord> buildManifests = advisoryManifestsRecord.manifests()
                        .stream()
                        .filter(manifest -> manifest.generation().id().equals(generationId))
                        .toList();
                Map<String, String> originalToRebuiltPurl = new HashMap<>();
                buildManifests.forEach(manifestRecord -> {
                    String rebuiltPurl = AdvisoryEventUtils.rebuildPurl(manifestRecord.rootPurl(), preferredRepo.get());
                    originalToRebuiltPurl.put(manifestRecord.rootPurl(), rebuiltPurl);
                    log.debug("Regenerated rootPurl '{}' to '{}'", manifestRecord.rootPurl(), rebuiltPurl);
                });

                // 2.3 - For every manifest previously generated from this generation
                for (V1Beta1RequestManifestRecord buildManifestRecord : buildManifests) {

                    Sbom buildManifest = sbomService.get(buildManifestRecord.id());
                    Bom manifestBom = SbomUtils.fromJsonNode(buildManifest.getSbom());
                    SbomUtils.addMissingMetadataSupplier(manifestBom);

                    // 2.4 Update rootPurl, metadata.component.purl, bom.component[0].purl with the rebuiltPurl
                    String rebuiltPurl = originalToRebuiltPurl.get(buildManifestRecord.rootPurl());
                    buildManifest.setRootPurl(rebuiltPurl);
                    log.debug("Updated manifest '{}' to rootPurl '{}'", buildManifestRecord.id(), rebuiltPurl);

                    SbomUtils.addPropertyIfMissing(
                            manifestBom.getMetadata(),
                            Constants.CONTAINER_PROPERTY_ADVISORY_ID,
                            String.valueOf(erratum.getDetails().get().getId()));

                    if (manifestBom.getMetadata() != null && manifestBom.getMetadata().getComponent() != null) {

                        manifestBom.getMetadata().getComponent().setPurl(rebuiltPurl);
                        String desc = manifestBom.getMetadata().getComponent().getDescription();
                        if (desc != null && desc.contains(buildManifest.getRootPurl())) {
                            manifestBom.getMetadata()
                                    .getComponent()
                                    .setDescription(desc.replace(buildManifest.getRootPurl(), rebuiltPurl));
                        }
                    }
                    if (SbomUtils.isNotEmpty(manifestBom.getComponents())) {
                        manifestBom.getComponents().get(0).setPurl(rebuiltPurl);

                        // 2.5 - If there are variants (this is an index image) update also the purls with the rebuilt
                        // ones
                        if (manifestBom.getComponents().get(0).getPedigree() != null
                                && manifestBom.getComponents().get(0).getPedigree().getVariants() != null
                                && manifestBom.getComponents()
                                        .get(0)
                                        .getPedigree()
                                        .getVariants()
                                        .getComponents() != null) {

                            for (Component variant : manifestBom.getComponents()
                                    .get(0)
                                    .getPedigree()
                                    .getVariants()
                                    .getComponents()) {
                                if (originalToRebuiltPurl.containsKey(variant.getPurl())) {
                                    variant.setPurl(originalToRebuiltPurl.get(variant.getPurl()));
                                }
                            }
                        }

                        // 2.6 - Add an evidence.identity list with all the rebuilt purls
                        Set<String> evidencePurls = AdvisoryEventUtils
                                .rebuildPurls(buildManifest.getRootPurl(), repositories);
                        log.debug("Rebuilt evidence purl '{}'", String.join(", ", evidencePurls));
                        SbomUtils.setEvidenceIdentities(manifestBom.getComponents().get(0), evidencePurls, Field.PURL);
                    }

                    // 2.7 - Update the original Sbom
                    buildManifest.setSbom(SbomUtils.toJsonNode(manifestBom));

                    // 2.8 - Add more information for this release so to find manifests more easily
                    ObjectNode buildManifestMetadataNode = collectReleaseInfo(
                            requestEvent.getId(),
                            erratum,
                            productVersion,
                            manifestBom);
                    buildManifest.setReleaseMetadata(buildManifestMetadataNode);
                    sboms.add(buildManifest);
                }
            }

            requestEvent = requestEventRepository.findById(requestEvent.getId());
            requestEvent.setEventStatus(RequestEventStatus.SUCCESS);
            QuarkusTransaction.commit();
            sboms.add(sbom); // For consistency upload release after build SBOMs

            return sboms;
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

    protected Map<ProductVersionEntry, List<BuildItem>> getAdvisoryBuildDetails(String advisoryId) {
        ErrataBuildList erratumBuildList = errataClient.getBuildsList(advisoryId);
        return erratumBuildList.getProductVersions()
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

    protected Map<ProductVersionEntry, Set<String>> mapProductVersionToCPEs(
            Map<ProductVersionEntry, List<BuildItem>> advisoryBuildDetails) {

        Map<ProductVersionEntry, Set<String>> productVersionToCPEs = new HashMap<>();
        advisoryBuildDetails.forEach((productVersionEntry, buildItems) -> {
            // Map all VariantArch to ErrataVariant and collect distinct ErrataVariant objects
            Set<String> productVersionCPEs = buildItems.stream()
                    .flatMap(buildItem -> buildItem.getVariantArch().keySet().stream())
                    .map(variantArch -> errataClient.getVariant(variantArch))
                    .filter(Objects::nonNull)
                    .map(errataVariant -> errataVariant.getData().getAttributes().getCpe())
                    .collect(Collectors.toSet());

            // Add more granular CPEs
            productVersionCPEs.addAll(AdvisoryEventUtils.createGranularCPEs(productVersionEntry, productVersionCPEs));

            productVersionToCPEs.put(productVersionEntry, productVersionCPEs);
        });
        return productVersionToCPEs;
    }

    protected List<RepositoryCoordinates> getRepositoriesDetails(String nvr) {
        log.debug("Getting repositories details from Pyxis for NVR '{}'", nvr);

        PyxisRepositoryDetails repositoriesDetails = pyxisClient
                .getRepositoriesDetails(nvr, REPOSITORIES_DETAILS_INCLUDES);
        return repositoriesDetails.getData()
                .stream()
                .flatMap(dataSection -> dataSection.getRepositories().stream())
                .filter(PyxisRepositoryDetails.Repository::isPublished)
                .filter(repository -> repository.getTags() != null)
                .flatMap(
                        repository -> repository.getTags()
                                .stream()
                                .filter(tag -> !"latest".equals(tag.getName()))
                                .map(
                                        tag -> new RepositoryCoordinates(
                                                repository.getRegistry(),
                                                repository.getRepository(),
                                                tag.getName())))
                .filter(repoCoordinate -> repoCoordinate.getRepositoryFragment() != null)
                .toList();
    }

    protected List<ErrataCDNRepoNormalized> getCDNDetails(BuildItem buildItem, String productShortName) {
        List<ErrataCDNRepoNormalized> allCDNs = new ArrayList<>();
        buildItem.getVariantArch()
                .keySet()
                .forEach(variant -> allCDNs.addAll(errataClient.getCDNReposOfVariant(variant, productShortName)));
        return allCDNs.stream().distinct().toList();
    }

    /*
     * Not used at the moment. Useful to understand if a repository has requires_terms = false meaning the repo is also
     * accessible without authentication
     */
    protected PyxisRepository getRepository(String registry, String repository) {
        return pyxisClient.getRepository(registry, repository, REPOSITORIES_REGISTRY_INCLUDES);
    }

    protected ObjectNode collectReleaseInfo(
            String requestEventId,
            Errata erratum,
            ProductVersionEntry versionEntry,
            Bom manifest) {
        ObjectNode releaseMetadata = ObjectMapperProvider.json().createObjectNode();
        releaseMetadata.put(REQUEST_ID, requestEventId);
        // FIXME: 'Optional.get()' without 'isPresent()' check
        releaseMetadata.put(ERRATA, erratum.getDetails().get().getFulladvisory());
        releaseMetadata.put(ERRATA_ID, erratum.getDetails().get().getId());
        if (erratum.getDetails().get().getActualShipDate() != null) {
            releaseMetadata.put(ERRATA_SHIP_DATE, Date.from(erratum.getDetails().get().getActualShipDate()).toString());
        }
        releaseMetadata.put(PRODUCT, versionEntry.getDescription());
        releaseMetadata.put(PRODUCT_SHORTNAME, erratum.getDetails().get().getProduct().getShortName());
        releaseMetadata.put(PRODUCT_VERSION, versionEntry.getName());

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

    private void adjustComponent(
            Component component,
            Collection<ErrataCDNRepoNormalized> generationCDNs,
            Set<String> manifestArches) {

        Set<String> evidencePurls = AdvisoryEventUtils.createPurls(component.getPurl(), generationCDNs, manifestArches);
        log.debug("Calculated evidence purls: {}", evidencePurls);
        String preferredRebuiltPurl = evidencePurls.stream().max(Comparator.comparingInt(String::length)).orElse(null);
        log.debug("Preferred rebuilt purl: {}", preferredRebuiltPurl);
        // The preferredRebuiltPurl is null if the component.getPurl() is not valid
        // or it does not contain any "arch" qualifier
        if (preferredRebuiltPurl != null) {
            component.setPurl(preferredRebuiltPurl);
            SbomUtils.setEvidenceIdentities(component, evidencePurls, Field.PURL);
        }
    }

    private V1Beta1RequestManifestRecord findImageIndexManifest(
            V1Beta1RequestRecord advisoryManifestsRecord,
            V1Beta1GenerationRecord generation) {

        String imageIndexPurl = SbomUtils.createContainerImageOCIPurl(generation.identifier());
        if (imageIndexPurl == null) {
            throw new ApplicationException("Unable to compute PURL for generation '{}'", generation.identifier());
        }
        return advisoryManifestsRecord.manifests()
                .stream()
                .filter(
                        manifest -> manifest.generation().id().equals(generation.id())
                                && manifest.rootPurl().equals(imageIndexPurl))
                .findFirst()
                .orElseThrow(
                        () -> new ApplicationException(
                                "Image index manifest not found for generation '{}'",
                                generation.identifier()));
    }

    private String getGenerationNVRFromManifest(V1Beta1RequestManifestRecord manifestRecord) {
        GenerationRequestType generationRequestType = GenerationRequestType
                .fromName(manifestRecord.generation().type());

        if (GenerationRequestType.BREW_RPM.equals(generationRequestType)) {
            // The NVR is stored as the generation identifier
            return manifestRecord.generation().identifier();
        }

        if (GenerationRequestType.CONTAINERIMAGE.equals(generationRequestType)) {
            // The NVR is not stored inside the generation, we need to get it from the manifest. Might be optimized in
            // the future.
            Sbom sbom = sbomService.get(manifestRecord.id());
            List<String> nvr = SbomUtils.computeNVRFromContainerManifest(sbom.getSbom());
            if (!nvr.isEmpty()) {
                return String.join(NVR_STANDARD_SEPARATOR, nvr);
            }
        }

        // There are no NVRs associated with GenerationRequestType.BUILD or GenerationRequestType.OPERATION or
        // GenerationRequestType.ANALYSIS
        return null;
    }

    private Map<String, V1Beta1GenerationRecord> mapNVRToBuildGeneration(V1Beta1RequestRecord advisoryManifestsRecord) {
        Set<String> processedGenerationsIds = new HashSet<>();

        return advisoryManifestsRecord.manifests()
                .stream()
                .filter(manifest -> !processedGenerationsIds.contains(manifest.generation().id()))
                .map(manifest -> {
                    String nvr = getGenerationNVRFromManifest(manifest);
                    if (nvr != null) {
                        processedGenerationsIds.add(manifest.generation().id());
                    }
                    // FIXME: nvr can be null here. It's filtered out later, but there may be a better way to handle
                    // this
                    return Map.entry(nvr, manifest.generation());
                })
                .filter(entry -> entry.getKey() != null) // Filter out entries where NVR is null
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    // Helper method to get all the architectures in the manifest
    private Set<String> getAllArchitectures(Bom bom) {
        Set<String> manifestArches = new HashSet<>();
        for (Component component : bom.getComponents()) {
            try {
                PackageURL purl = new PackageURL(component.getPurl());
                Map<String, String> qualifiers = purl.getQualifiers();
                if (qualifiers != null) {
                    String archValue = qualifiers.get("arch");
                    if (archValue != null && !"src".equals(archValue)) {
                        manifestArches.add(archValue);
                    }
                }
            } catch (MalformedPackageURLException e) {
                log.debug(
                        "Unable to parse the purl '{}' of component with name '{}' ({})",
                        component.getPurl(),
                        component.getName(),
                        e.getMessage());
            }
        }
        return manifestArches;
    }

}
