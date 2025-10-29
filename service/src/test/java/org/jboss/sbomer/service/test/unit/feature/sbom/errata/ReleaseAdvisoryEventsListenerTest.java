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
package org.jboss.sbomer.service.test.unit.feature.sbom.errata;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Identity.Field;
import org.jboss.sbomer.core.dto.v1beta1.V1Beta1RequestRecord;
import org.jboss.sbomer.core.features.sbom.Constants;
import org.jboss.sbomer.core.features.sbom.enums.GenerationRequestType;
import org.jboss.sbomer.core.features.sbom.enums.RequestEventStatus;
import org.jboss.sbomer.core.features.sbom.utils.GenericPurlWrapperUtil;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.core.test.TestResources;
import org.jboss.sbomer.service.feature.sbom.atlas.AtlasHandler;
import org.jboss.sbomer.service.feature.sbom.errata.ErrataClient;
import org.jboss.sbomer.service.feature.sbom.errata.dto.Errata;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataBuildList;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataBuildList.BuildItem;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataBuildList.ProductVersionEntry;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataCDNRepo;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataCDNRepoNormalized;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataVariant;
import org.jboss.sbomer.service.feature.sbom.errata.event.release.ReleaseStandardAdvisoryEventsListener;
import org.jboss.sbomer.service.feature.sbom.errata.event.release.ReleaseTextOnlyAdvisoryEventsListener;
import org.jboss.sbomer.service.feature.sbom.errata.event.release.StandardAdvisoryReleaseEvent;
import org.jboss.sbomer.service.feature.sbom.errata.event.release.TextOnlyAdvisoryReleaseEvent;
import org.jboss.sbomer.service.feature.sbom.errata.event.util.MdcEventWrapper;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationStatus;
import org.jboss.sbomer.service.feature.sbom.model.RandomStringIdGenerator;
import org.jboss.sbomer.service.feature.sbom.model.RequestEvent;
import org.jboss.sbomer.service.feature.sbom.model.Sbom;
import org.jboss.sbomer.service.feature.sbom.model.SbomGenerationRequest;
import org.jboss.sbomer.service.feature.sbom.model.Stats;
import org.jboss.sbomer.service.feature.sbom.pyxis.PyxisValidatingClient;
import org.jboss.sbomer.service.feature.sbom.pyxis.dto.PyxisRepositoryDetails;
import org.jboss.sbomer.service.feature.sbom.pyxis.dto.RepositoryCoordinates;
import org.jboss.sbomer.service.feature.sbom.service.RequestEventRepository;
import org.jboss.sbomer.service.feature.sbom.service.SbomGenerationRequestRepository;
import org.jboss.sbomer.service.feature.sbom.service.SbomService;
import org.jboss.sbomer.service.stats.StatsService;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.packageurl.MalformedPackageURLException;

import groovy.util.logging.Slf4j;
import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
@Slf4j
class ReleaseAdvisoryEventsListenerTest {

    ReleaseAdvisoryEventsListenerSingleContainer listenerSingleContainer;
    ReleaseAdvisoryEventsListenerMultiContainer listenerMultiContainers;
    ReleaseAdvisoryEventsListenerSingleRPM listenerSingleRpm;
    ReleaseTextOnlyAdvisoryEventsListenerManifests listenerTextOnlyManifests;
    ReleaseTextOnlyAdvisoryEventsListenerDeliverables listenerTextOnlyDeliverables;
    final ErrataClient errataClient = mock(ErrataClient.class);
    final PyxisValidatingClient pyxisClient = mock(PyxisValidatingClient.class);
    final StatsService statsService = mock(StatsService.class);
    final SbomService sbomService = mock(SbomService.class);
    final SbomGenerationRequestRepository generationRequestRepository = mock(SbomGenerationRequestRepository.class);
    final RequestEventRepository requestEventRepository = mock(RequestEventRepository.class);
    final AtlasHandler atlasHandler = mock(AtlasHandler.class);

    private static void printRawBom(Bom bom) {
        try {
            String jsonString = ObjectMapperProvider.json()
                    .enable(SerializationFeature.INDENT_OUTPUT)
                    .writeValueAsString(bom);
            System.out.println(jsonString);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
    }

    private static void validateComponent(
            Component component,
            Component.Type expectedType,
            String expectedGroup,
            String expectedName,
            String expectedVersion,
            String expectedBomRef,
            String expectedPurl,
            List<String> expectedConcludedValues,
            Field expectedField) {

        if (expectedGroup != null) {
            assertEquals(expectedGroup, component.getGroup());
        }
        assertEquals(expectedType, component.getType());
        assertEquals(expectedName, component.getName());
        assertEquals(expectedVersion, component.getVersion());
        assertEquals(expectedBomRef, component.getBomRef());

        assertEquals(expectedPurl, component.getPurl());

        List<Identity> identities = component.getEvidence().getIdentities();
        assertEquals(expectedConcludedValues.size(), identities.size());
        for (int i = 0; i < expectedConcludedValues.size(); i++) {
            assertEquals(expectedConcludedValues.get(i), identities.get(i).getConcludedValue());
            assertEquals(expectedField, identities.get(i).getField());
        }
    }

    private static void validateDependencies(
            List<Dependency> dependencies,
            int expectedDepSize,
            String expectedMainDepRef,
            List<String> expectedProvidesRef) {
        assertEquals(expectedDepSize, dependencies.size());
        assertEquals(expectedMainDepRef, dependencies.get(0).getRef());
        assertNull(dependencies.get(0).getDependencies());
        assertEquals(expectedProvidesRef.size(), dependencies.get(0).getProvides().size());
        for (int i = 0; i < expectedProvidesRef.size(); i++) {
            assertEquals(expectedProvidesRef.get(i), dependencies.get(0).getProvides().get(i).getRef());
        }
    }

    private static void validateProperty(List<Property> properties, String pName, String pValue) {
        Optional<Property> advisoryIdProperty = SbomUtils
                .findPropertyWithName(Constants.CONTAINER_PROPERTY_ADVISORY_ID, properties);
        assertTrue(advisoryIdProperty.isPresent());
        assertEquals(pValue, advisoryIdProperty.get().getValue());
    }

    static class ReleaseAdvisoryEventsListenerSingleContainer extends ReleaseStandardAdvisoryEventsListener {

        @Override
        protected List<Sbom> saveReleaseManifestForDockerGeneration(
                RequestEvent requestEvent,
                Errata erratum,
                ProductVersionEntry productVersion,
                String toolVersion,
                SbomGenerationRequest releaseGeneration,
                Bom bom,
                V1Beta1RequestRecord advisoryManifestsRecord,
                Map<String, List<RepositoryCoordinates>> generationToRepositories) {

            validateComponent(
                    bom.getMetadata().getComponent(),
                    Component.Type.OPERATING_SYSTEM,
                    null,
                    "Red Hat Enterprise Linux 8",
                    "RHEL-8.10.0.Z.MAIN+EUS",
                    "RHEL-8.10.0.Z.MAIN+EUS",
                    null,
                    List.of(
                            "cpe:/a:redhat:enterprise_linux:8.10::appstream",
                            "cpe:/a:redhat:enterprise_linux:8::appstream"),
                    Field.CPE);

            validateComponent(
                    bom.getComponents().get(0),
                    Component.Type.CONTAINER,
                    null,
                    "ubi8/ruby-25",
                    "sha256:b1f140e930baffe400e412fbf04d57624a18593e77fcc5cfa1b2462a3f85fc94",
                    "pkg:oci/ruby-25@sha256%3Ab1f140e930baffe400e412fbf04d57624a18593e77fcc5cfa1b2462a3f85fc94",
                    "pkg:oci/ruby-25@sha256%3Ab1f140e930baffe400e412fbf04d57624a18593e77fcc5cfa1b2462a3f85fc94",
                    List.of(
                            "pkg:oci/ruby-25@sha256%3Ab1f140e930baffe400e412fbf04d57624a18593e77fcc5cfa1b2462a3f85fc94?repository_url=registry.access.redhat.com%2Frhel8%2Fruby-25&tag=1-260.1733408998",
                            "pkg:oci/ruby-25@sha256%3Ab1f140e930baffe400e412fbf04d57624a18593e77fcc5cfa1b2462a3f85fc94?repository_url=registry.access.redhat.com%2Fubi8%2Fruby-25&tag=1-260.1733408998",
                            "pkg:oci/ruby-25@sha256%3Ab1f140e930baffe400e412fbf04d57624a18593e77fcc5cfa1b2462a3f85fc94?repository_url=registry.access.redhat.com%2Frhel8%2Fruby-25&tag=1",
                            "pkg:oci/ruby-25@sha256%3Ab1f140e930baffe400e412fbf04d57624a18593e77fcc5cfa1b2462a3f85fc94?repository_url=registry.access.redhat.com%2Fubi8%2Fruby-25&tag=1"),
                    Field.PURL);

            validateDependencies(
                    bom.getDependencies(),
                    1,
                    "RHEL-8.10.0.Z.MAIN+EUS",
                    List.of(
                            "pkg:oci/ruby-25@sha256%3Ab1f140e930baffe400e412fbf04d57624a18593e77fcc5cfa1b2462a3f85fc94"));

            validateProperty(
                    bom.getMetadata().getProperties(),
                    Constants.CONTAINER_PROPERTY_ADVISORY_ID,
                    String.valueOf(erratum.getDetails().get().getId()));
            printRawBom(bom);
            return List.of(new Sbom());
        }
    }

    static class ReleaseAdvisoryEventsListenerMultiContainer extends ReleaseStandardAdvisoryEventsListener {

        @Override
        protected List<Sbom> saveReleaseManifestForDockerGeneration(
                RequestEvent requestEvent,
                Errata erratum,
                ProductVersionEntry productVersion,
                String toolVersion,
                SbomGenerationRequest releaseGeneration,
                Bom bom,
                V1Beta1RequestRecord advisoryManifestsRecord,
                Map<String, List<RepositoryCoordinates>> generationToRepositories) {

            assertTrue(
                    bom.getMetadata().getComponent().getVersion().equals("OSE-4.15-RHEL-8")
                            || bom.getMetadata().getComponent().getVersion().equals("OSE-4.15-RHEL-9"));

            if (bom.getMetadata().getComponent().getVersion().equals("OSE-4.15-RHEL-8")) {

                validateComponent(
                        bom.getMetadata().getComponent(),
                        Component.Type.FRAMEWORK,
                        null,
                        "Red Hat OpenShift Container Platform 4.15",
                        "OSE-4.15-RHEL-8",
                        "OSE-4.15-RHEL-8",
                        null,
                        List.of("cpe:/a:redhat:openshift:4.15::el8"),
                        Field.CPE);

                validateComponent(
                        bom.getComponents().get(0),
                        Component.Type.CONTAINER,
                        null,
                        "openshift/ose-gcp-filestore-csi-driver-operator-bundle",
                        "sha256:201088e8a5c8a59bac4f8bc796542fb76b162e68e5af521f8dd56d05446f52f4",
                        "pkg:oci/ose-gcp-filestore-csi-driver-operator-bundle@sha256%3A201088e8a5c8a59bac4f8bc796542fb76b162e68e5af521f8dd56d05446f52f4",
                        "pkg:oci/ose-gcp-filestore-csi-driver-operator-bundle@sha256%3A201088e8a5c8a59bac4f8bc796542fb76b162e68e5af521f8dd56d05446f52f4",
                        List.of(
                                "pkg:oci/ose-gcp-filestore-csi-driver-operator-bundle@sha256%3A201088e8a5c8a59bac4f8bc796542fb76b162e68e5af521f8dd56d05446f52f4?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-gcp-filestore-csi-driver-operator-bundle&tag=v4.15.0.202412041605.p0.ga923e95.assembly.stream.el8-2",
                                "pkg:oci/ose-gcp-filestore-csi-driver-operator-bundle@sha256%3A201088e8a5c8a59bac4f8bc796542fb76b162e68e5af521f8dd56d05446f52f4?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-gcp-filestore-csi-driver-operator-bundle&tag=v4.15.0.202412041605.p0.ga923e95.assembly.stream.el8",
                                "pkg:oci/ose-gcp-filestore-csi-driver-operator-bundle@sha256%3A201088e8a5c8a59bac4f8bc796542fb76b162e68e5af521f8dd56d05446f52f4?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-gcp-filestore-csi-driver-operator-bundle&tag=v4.15"),
                        Field.PURL);

                validateDependencies(
                        bom.getDependencies(),
                        1,
                        "OSE-4.15-RHEL-8",
                        List.of(
                                "pkg:oci/ose-gcp-filestore-csi-driver-operator-bundle@sha256%3A201088e8a5c8a59bac4f8bc796542fb76b162e68e5af521f8dd56d05446f52f4",
                                "pkg:oci/ose-aws-efs-csi-driver-operator-bundle@sha256%3A6e697d697a394f08cb9a669c7a85cb867e02fbfba79848390a518771ad3558cf",
                                "pkg:oci/ose-secrets-store-csi-driver-operator-bundle@sha256%3Ac3eb47f4c962949a1f8446de39963f20b299fbd1bf27e742232f1a9c144e7be0"));

            } else if (bom.getMetadata().getComponent().getVersion().equals("OSE-4.15-RHEL-9")) {

                validateComponent(
                        bom.getMetadata().getComponent(),
                        Component.Type.FRAMEWORK,
                        null,
                        "Red Hat OpenShift Container Platform 4.15",
                        "OSE-4.15-RHEL-9",
                        "OSE-4.15-RHEL-9",
                        null,
                        List.of("cpe:/a:redhat:openshift:4.15::el9"),
                        Field.CPE);

                validateComponent(
                        bom.getComponents().get(0),
                        Component.Type.CONTAINER,
                        null,
                        "openshift/ose-clusterresourceoverride-operator-bundle",
                        "sha256:d37ea60be41f378e0d3b9c0936d8c3fb0e218e00b8cdc3c073a3e35d494f3e8d",
                        "pkg:oci/ose-clusterresourceoverride-operator-bundle@sha256%3Ad37ea60be41f378e0d3b9c0936d8c3fb0e218e00b8cdc3c073a3e35d494f3e8d",
                        "pkg:oci/ose-clusterresourceoverride-operator-bundle@sha256%3Ad37ea60be41f378e0d3b9c0936d8c3fb0e218e00b8cdc3c073a3e35d494f3e8d",
                        List.of(
                                "pkg:oci/ose-clusterresourceoverride-operator-bundle@sha256%3Ad37ea60be41f378e0d3b9c0936d8c3fb0e218e00b8cdc3c073a3e35d494f3e8d?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-clusterresourceoverride-operator-bundle&tag=v4.15.0.202412021736.p0.g40c168c.assembly.stream.el9-1",
                                "pkg:oci/ose-clusterresourceoverride-operator-bundle@sha256%3Ad37ea60be41f378e0d3b9c0936d8c3fb0e218e00b8cdc3c073a3e35d494f3e8d?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-clusterresourceoverride-operator-bundle&tag=v4.15.0.202412021736.p0.g40c168c.assembly.stream.el9",
                                "pkg:oci/ose-clusterresourceoverride-operator-bundle@sha256%3Ad37ea60be41f378e0d3b9c0936d8c3fb0e218e00b8cdc3c073a3e35d494f3e8d?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-clusterresourceoverride-operator-bundle&tag=v4.15"),
                        Field.PURL);

                validateDependencies(
                        bom.getDependencies(),
                        1,
                        "OSE-4.15-RHEL-9",
                        List.of(
                                "pkg:oci/ose-clusterresourceoverride-operator-bundle@sha256%3Ad37ea60be41f378e0d3b9c0936d8c3fb0e218e00b8cdc3c073a3e35d494f3e8d",
                                "pkg:oci/ose-vertical-pod-autoscaler-operator-bundle@sha256%3A0c1507509cd03b183011726b11dc0f7834af8a097c9ffd5a4b389b8f2eae3bad",
                                "pkg:oci/openshift-ose-cluster-nfd-operator-bundle@sha256%3A3b8a3f00c2eb483d25ad43a44e0140f699cd4d7a9a5c4f43e2eecc21ea8a6771",
                                "pkg:oci/openshift-ose-ingress-node-firewall-operator-bundle@sha256%3A13f5bc757b25b359680938a06bbc83609b87f6797ede99f97953e5464ed380ef",
                                "pkg:oci/openshift-ose-local-storage-operator-bundle@sha256%3A20f5923ea4ba9fdef4779efb1423274b479efbb1278dd13010518a159cf32e37",
                                "pkg:oci/openshift-ose-metallb-operator-bundle@sha256%3A28b9c5ae08d95f9ae01bbf9fabab2d0bb7c93104243652e2b934dace47e3426d",
                                "pkg:oci/openshift-ose-openshift-kubernetes-nmstate-operator-bundle@sha256%3A20c3af0b0c80da26b4ea948b705e073d9df7181e58852a89ec6ee783933f4275",
                                "pkg:oci/openshift-ose-ptp-operator-bundle@sha256%3Af0bcb875bc379e1c6a2508796d69febe3891c5717956bcade2e1df6708f376b9"));
            }

            printRawBom(bom);

            Sbom sbom = Sbom.builder()
                    .withIdentifier(releaseGeneration.getIdentifier())
                    .withSbom(SbomUtils.toJsonNode(bom))
                    .withGenerationRequest(releaseGeneration)
                    .withConfigIndex(0)
                    .build();

            // Add more information for this release so to find manifests more easily
            ObjectNode metadataNode = collectReleaseInfo(requestEvent.getId(), erratum, productVersion, bom);
            sbom.setReleaseMetadata(metadataNode);

            assertEquals(
                    "E2DDBAB2B3A94E6",
                    metadataNode.get(ReleaseStandardAdvisoryEventsListener.REQUEST_ID).asText());
            assertEquals("RHBA-2024:10840-02", metadataNode.get(ReleaseStandardAdvisoryEventsListener.ERRATA).asText());
            assertEquals("143781", metadataNode.get(ReleaseStandardAdvisoryEventsListener.ERRATA_ID).asText());
            assertEquals(
                    "Red Hat OpenShift Container Platform 4.15",
                    metadataNode.get(ReleaseStandardAdvisoryEventsListener.PRODUCT).asText());
            assertEquals("RHOSE", metadataNode.get(ReleaseStandardAdvisoryEventsListener.PRODUCT_SHORTNAME).asText());

            String productVersionString = null;
            List<String> allPurls = new ArrayList<>();
            if (bom.getMetadata().getComponent().getVersion().equals("OSE-4.15-RHEL-8")) {

                productVersionString = "OSE-4.15-RHEL-8";
                allPurls = List.of(
                        "pkg:oci/ose-aws-efs-csi-driver-operator-bundle@sha256%3A6e697d697a394f08cb9a669c7a85cb867e02fbfba79848390a518771ad3558cf",
                        "pkg:oci/ose-aws-efs-csi-driver-operator-bundle@sha256%3A6e697d697a394f08cb9a669c7a85cb867e02fbfba79848390a518771ad3558cf?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-aws-efs-csi-driver-operator-bundle&tag=v4.15",
                        "pkg:oci/ose-aws-efs-csi-driver-operator-bundle@sha256%3A6e697d697a394f08cb9a669c7a85cb867e02fbfba79848390a518771ad3558cf?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-aws-efs-csi-driver-operator-bundle&tag=v4.15.0.202412041605.p0.gb0f13a0.assembly.stream.el8",
                        "pkg:oci/ose-aws-efs-csi-driver-operator-bundle@sha256%3A6e697d697a394f08cb9a669c7a85cb867e02fbfba79848390a518771ad3558cf?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-aws-efs-csi-driver-operator-bundle&tag=v4.15.0.202412041605.p0.gb0f13a0.assembly.stream.el8-2",
                        "pkg:oci/ose-gcp-filestore-csi-driver-operator-bundle@sha256%3A201088e8a5c8a59bac4f8bc796542fb76b162e68e5af521f8dd56d05446f52f4",
                        "pkg:oci/ose-gcp-filestore-csi-driver-operator-bundle@sha256%3A201088e8a5c8a59bac4f8bc796542fb76b162e68e5af521f8dd56d05446f52f4?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-gcp-filestore-csi-driver-operator-bundle&tag=v4.15",
                        "pkg:oci/ose-gcp-filestore-csi-driver-operator-bundle@sha256%3A201088e8a5c8a59bac4f8bc796542fb76b162e68e5af521f8dd56d05446f52f4?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-gcp-filestore-csi-driver-operator-bundle&tag=v4.15.0.202412041605.p0.ga923e95.assembly.stream.el8",
                        "pkg:oci/ose-gcp-filestore-csi-driver-operator-bundle@sha256%3A201088e8a5c8a59bac4f8bc796542fb76b162e68e5af521f8dd56d05446f52f4?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-gcp-filestore-csi-driver-operator-bundle&tag=v4.15.0.202412041605.p0.ga923e95.assembly.stream.el8-2",
                        "pkg:oci/ose-secrets-store-csi-driver-operator-bundle@sha256%3Ac3eb47f4c962949a1f8446de39963f20b299fbd1bf27e742232f1a9c144e7be0",
                        "pkg:oci/ose-secrets-store-csi-driver-operator-bundle@sha256%3Ac3eb47f4c962949a1f8446de39963f20b299fbd1bf27e742232f1a9c144e7be0?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-secrets-store-csi-driver-operator-bundle&tag=v4.15",
                        "pkg:oci/ose-secrets-store-csi-driver-operator-bundle@sha256%3Ac3eb47f4c962949a1f8446de39963f20b299fbd1bf27e742232f1a9c144e7be0?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-secrets-store-csi-driver-operator-bundle&tag=v4.15.0.202412041605.p0.gef602a5.assembly.stream.el8",
                        "pkg:oci/ose-secrets-store-csi-driver-operator-bundle@sha256%3Ac3eb47f4c962949a1f8446de39963f20b299fbd1bf27e742232f1a9c144e7be0?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-secrets-store-csi-driver-operator-bundle&tag=v4.15.0.202412041605.p0.gef602a5.assembly.stream.el8-2");
            } else if (bom.getMetadata().getComponent().getVersion().equals("OSE-4.15-RHEL-9")) {

                productVersionString = "OSE-4.15-RHEL-9";
                allPurls = List.of(
                        "pkg:oci/openshift-ose-cluster-nfd-operator-bundle@sha256%3A3b8a3f00c2eb483d25ad43a44e0140f699cd4d7a9a5c4f43e2eecc21ea8a6771",
                        "pkg:oci/openshift-ose-cluster-nfd-operator-bundle@sha256%3A3b8a3f00c2eb483d25ad43a44e0140f699cd4d7a9a5c4f43e2eecc21ea8a6771?repository_url=registry-proxy.engineering.redhat.com%2Frh-osbs%2Fopenshift-ose-cluster-nfd-operator-bundle&tag=rhaos-4.15-rhel-9-candidate-13298-20241205140058-x86_64",
                        "pkg:oci/openshift-ose-cluster-nfd-operator-bundle@sha256%3A3b8a3f00c2eb483d25ad43a44e0140f699cd4d7a9a5c4f43e2eecc21ea8a6771?repository_url=registry-proxy.engineering.redhat.com%2Frh-osbs%2Fopenshift-ose-cluster-nfd-operator-bundle&tag=v4.15.0.202412041605.p0.gabdfb61.assembly.stream.el9-2",
                        "pkg:oci/openshift-ose-ingress-node-firewall-operator-bundle@sha256%3A13f5bc757b25b359680938a06bbc83609b87f6797ede99f97953e5464ed380ef",
                        "pkg:oci/openshift-ose-ingress-node-firewall-operator-bundle@sha256%3A13f5bc757b25b359680938a06bbc83609b87f6797ede99f97953e5464ed380ef?repository_url=registry-proxy.engineering.redhat.com%2Frh-osbs%2Fopenshift-ose-ingress-node-firewall-operator-bundle&tag=rhaos-4.15-rhel-9-candidate-39757-20241205140103-x86_64",
                        "pkg:oci/openshift-ose-ingress-node-firewall-operator-bundle@sha256%3A13f5bc757b25b359680938a06bbc83609b87f6797ede99f97953e5464ed380ef?repository_url=registry-proxy.engineering.redhat.com%2Frh-osbs%2Fopenshift-ose-ingress-node-firewall-operator-bundle&tag=v4.15.0.202412041605.p0.g135f832.assembly.stream.el9-2",
                        "pkg:oci/openshift-ose-local-storage-operator-bundle@sha256%3A20f5923ea4ba9fdef4779efb1423274b479efbb1278dd13010518a159cf32e37",
                        "pkg:oci/openshift-ose-local-storage-operator-bundle@sha256%3A20f5923ea4ba9fdef4779efb1423274b479efbb1278dd13010518a159cf32e37?repository_url=registry-proxy.engineering.redhat.com%2Frh-osbs%2Fopenshift-ose-local-storage-operator-bundle&tag=rhaos-4.15-rhel-9-candidate-48857-20241205140324-x86_64",
                        "pkg:oci/openshift-ose-local-storage-operator-bundle@sha256%3A20f5923ea4ba9fdef4779efb1423274b479efbb1278dd13010518a159cf32e37?repository_url=registry-proxy.engineering.redhat.com%2Frh-osbs%2Fopenshift-ose-local-storage-operator-bundle&tag=v4.15.0.202412041605.p0.gcc4f213.assembly.stream.el9-2",
                        "pkg:oci/openshift-ose-metallb-operator-bundle@sha256%3A28b9c5ae08d95f9ae01bbf9fabab2d0bb7c93104243652e2b934dace47e3426d",
                        "pkg:oci/openshift-ose-metallb-operator-bundle@sha256%3A28b9c5ae08d95f9ae01bbf9fabab2d0bb7c93104243652e2b934dace47e3426d?repository_url=registry-proxy.engineering.redhat.com%2Frh-osbs%2Fopenshift-ose-metallb-operator-bundle&tag=rhaos-4.15-rhel-9-candidate-87210-20241205140408-x86_64",
                        "pkg:oci/openshift-ose-metallb-operator-bundle@sha256%3A28b9c5ae08d95f9ae01bbf9fabab2d0bb7c93104243652e2b934dace47e3426d?repository_url=registry-proxy.engineering.redhat.com%2Frh-osbs%2Fopenshift-ose-metallb-operator-bundle&tag=v4.15.0.202412041605.p0.g359620b.assembly.stream.el9-2",
                        "pkg:oci/openshift-ose-openshift-kubernetes-nmstate-operator-bundle@sha256%3A20c3af0b0c80da26b4ea948b705e073d9df7181e58852a89ec6ee783933f4275",
                        "pkg:oci/openshift-ose-openshift-kubernetes-nmstate-operator-bundle@sha256%3A20c3af0b0c80da26b4ea948b705e073d9df7181e58852a89ec6ee783933f4275?repository_url=registry-proxy.engineering.redhat.com%2Frh-osbs%2Fopenshift-ose-openshift-kubernetes-nmstate-operator-bundle&tag=rhaos-4.15-rhel-9-candidate-15150-20241205140452-x86_64",
                        "pkg:oci/openshift-ose-openshift-kubernetes-nmstate-operator-bundle@sha256%3A20c3af0b0c80da26b4ea948b705e073d9df7181e58852a89ec6ee783933f4275?repository_url=registry-proxy.engineering.redhat.com%2Frh-osbs%2Fopenshift-ose-openshift-kubernetes-nmstate-operator-bundle&tag=v4.15.0.202412041605.p0.g0d290b4.assembly.stream.el9-2",
                        "pkg:oci/openshift-ose-ptp-operator-bundle@sha256%3Af0bcb875bc379e1c6a2508796d69febe3891c5717956bcade2e1df6708f376b9",
                        "pkg:oci/openshift-ose-ptp-operator-bundle@sha256%3Af0bcb875bc379e1c6a2508796d69febe3891c5717956bcade2e1df6708f376b9?repository_url=registry-proxy.engineering.redhat.com%2Frh-osbs%2Fopenshift-ose-ptp-operator-bundle&tag=rhaos-4.15-rhel-9-candidate-31211-20241205140840-x86_64",
                        "pkg:oci/openshift-ose-ptp-operator-bundle@sha256%3Af0bcb875bc379e1c6a2508796d69febe3891c5717956bcade2e1df6708f376b9?repository_url=registry-proxy.engineering.redhat.com%2Frh-osbs%2Fopenshift-ose-ptp-operator-bundle&tag=v4.15.0.202412041605.p0.g6fb51fd.assembly.stream.el9-2",
                        "pkg:oci/ose-clusterresourceoverride-operator-bundle@sha256%3Ad37ea60be41f378e0d3b9c0936d8c3fb0e218e00b8cdc3c073a3e35d494f3e8d",
                        "pkg:oci/ose-clusterresourceoverride-operator-bundle@sha256%3Ad37ea60be41f378e0d3b9c0936d8c3fb0e218e00b8cdc3c073a3e35d494f3e8d?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-clusterresourceoverride-operator-bundle&tag=v4.15",
                        "pkg:oci/ose-clusterresourceoverride-operator-bundle@sha256%3Ad37ea60be41f378e0d3b9c0936d8c3fb0e218e00b8cdc3c073a3e35d494f3e8d?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-clusterresourceoverride-operator-bundle&tag=v4.15.0.202412021736.p0.g40c168c.assembly.stream.el9",
                        "pkg:oci/ose-clusterresourceoverride-operator-bundle@sha256%3Ad37ea60be41f378e0d3b9c0936d8c3fb0e218e00b8cdc3c073a3e35d494f3e8d?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-clusterresourceoverride-operator-bundle&tag=v4.15.0.202412021736.p0.g40c168c.assembly.stream.el9-1",
                        "pkg:oci/ose-vertical-pod-autoscaler-operator-bundle@sha256%3A0c1507509cd03b183011726b11dc0f7834af8a097c9ffd5a4b389b8f2eae3bad",
                        "pkg:oci/ose-vertical-pod-autoscaler-operator-bundle@sha256%3A0c1507509cd03b183011726b11dc0f7834af8a097c9ffd5a4b389b8f2eae3bad?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-vertical-pod-autoscaler-operator-bundle&tag=v4.15",
                        "pkg:oci/ose-vertical-pod-autoscaler-operator-bundle@sha256%3A0c1507509cd03b183011726b11dc0f7834af8a097c9ffd5a4b389b8f2eae3bad?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-vertical-pod-autoscaler-operator-bundle&tag=v4.15.0.202412021736.p0.g8876256.assembly.stream.el9",
                        "pkg:oci/ose-vertical-pod-autoscaler-operator-bundle@sha256%3A0c1507509cd03b183011726b11dc0f7834af8a097c9ffd5a4b389b8f2eae3bad?repository_url=registry.access.redhat.com%2Fopenshift4%2Fose-vertical-pod-autoscaler-operator-bundle&tag=v4.15.0.202412021736.p0.g8876256.assembly.stream.el9-1");
            }
            assertEquals(
                    productVersionString,
                    metadataNode.get(ReleaseStandardAdvisoryEventsListener.PRODUCT_VERSION).asText());
            ArrayNode arrayNode = (ArrayNode) metadataNode.get(ReleaseStandardAdvisoryEventsListener.PURL_LIST);
            for (int i = 0; i < arrayNode.size(); i++) {
                JsonNode node = arrayNode.get(i);
                assertEquals(node.asText(), allPurls.get(i));
            }
            validateProperty(
                    bom.getMetadata().getProperties(),
                    Constants.CONTAINER_PROPERTY_ADVISORY_ID,
                    String.valueOf(erratum.getDetails().get().getId()));
            return List.of(sbom);
        }
    }

    static class ReleaseAdvisoryEventsListenerSingleRPM extends ReleaseStandardAdvisoryEventsListener {

        @Override
        protected List<Sbom> saveReleaseManifestForRPMGeneration(
                RequestEvent requestEvent,
                Errata erratum,
                ProductVersionEntry productVersion,
                String toolVersion,
                SbomGenerationRequest releaseGeneration,
                Bom bom,
                V1Beta1RequestRecord advisoryManifestsRecord,
                Map<String, List<ErrataCDNRepoNormalized>> generationToCDNs) {

            validateComponent(
                    bom.getMetadata().getComponent(),
                    Component.Type.OPERATING_SYSTEM,
                    null,
                    "Red Hat Enterprise Linux 7",
                    "RHEL-7.2.Z",
                    "RHEL-7.2.Z",
                    null,
                    List.of(
                            "cpe:/o:redhat:enterprise_linux:7.2::computenode",
                            "cpe:/o:redhat:enterprise_linux:7::computenode"),
                    Field.CPE);

            validateComponent(
                    bom.getComponents().get(0),
                    Component.Type.LIBRARY,
                    null,
                    "redhat-release-computenode",
                    "7.2-8.el7_2.1",
                    "pkg:rpm/redhat/redhat-release-computenode@7.2-8.el7_2.1?arch=src",
                    "pkg:rpm/redhat/redhat-release-computenode@7.2-8.el7_2.1?arch=src",
                    List.of(
                            "pkg:rpm/redhat/redhat-release-computenode@7.2-8.el7_2.1?arch=src&repository_id=rhel-7-hpc-node-source-rpms__7ComputeNode__x86_64",
                            "pkg:rpm/redhat/redhat-release-computenode@7.2-8.el7_2.1?arch=src&repository_id=rhel-7-hpc-node-eus-source-rpms__7_DOT_2__x86_64"),
                    Field.PURL);

            validateDependencies(
                    bom.getDependencies(),
                    1,
                    "RHEL-7.2.Z",
                    List.of("pkg:rpm/redhat/redhat-release-computenode@7.2-8.el7_2.1?arch=src"));

            printRawBom(bom);

            Sbom sbom = Sbom.builder()
                    .withIdentifier(releaseGeneration.getIdentifier())
                    .withSbom(SbomUtils.toJsonNode(bom))
                    .withGenerationRequest(releaseGeneration)
                    .withConfigIndex(0)
                    .build();

            // Add more information for this release so to find manifests more easily
            ObjectNode metadataNode = collectReleaseInfo(requestEvent.getId(), erratum, productVersion, bom);
            sbom.setReleaseMetadata(metadataNode);

            assertEquals(
                    "4186BB34453E473",
                    metadataNode.get(ReleaseStandardAdvisoryEventsListener.REQUEST_ID).asText());
            assertEquals("RHBA-2024:89769-01", metadataNode.get(ReleaseStandardAdvisoryEventsListener.ERRATA).asText());
            assertEquals("89769", metadataNode.get(ReleaseStandardAdvisoryEventsListener.ERRATA_ID).asText());
            assertEquals(
                    "Red Hat Enterprise Linux 7",
                    metadataNode.get(ReleaseStandardAdvisoryEventsListener.PRODUCT).asText());
            assertEquals("RHEL", metadataNode.get(ReleaseStandardAdvisoryEventsListener.PRODUCT_SHORTNAME).asText());
            assertEquals(
                    "RHEL-7.2.Z",
                    metadataNode.get(ReleaseStandardAdvisoryEventsListener.PRODUCT_VERSION).asText());

            ArrayNode arrayNode = (ArrayNode) metadataNode.get(ReleaseStandardAdvisoryEventsListener.PURL_LIST);
            List<String> allPurls = List.of(
                    "pkg:rpm/redhat/redhat-release-computenode@7.2-8.el7_2.1?arch=src",
                    "pkg:rpm/redhat/redhat-release-computenode@7.2-8.el7_2.1?arch=src&repository_id=rhel-7-hpc-node-eus-source-rpms__7_DOT_2__x86_64",
                    "pkg:rpm/redhat/redhat-release-computenode@7.2-8.el7_2.1?arch=src&repository_id=rhel-7-hpc-node-source-rpms__7ComputeNode__x86_64");

            for (int i = 0; i < arrayNode.size(); i++) {
                JsonNode node = arrayNode.get(i);
                assertEquals(node.asText(), allPurls.get(i));
            }
            validateProperty(
                    bom.getMetadata().getProperties(),
                    Constants.CONTAINER_PROPERTY_ADVISORY_ID,
                    String.valueOf(erratum.getDetails().get().getId()));
            return List.of(sbom);
        }
    }

    static class ReleaseTextOnlyAdvisoryEventsListenerManifests extends ReleaseTextOnlyAdvisoryEventsListener {
        @Override
        protected List<Sbom> saveReleaseManifestForTextOnlyAdvisories(
                RequestEvent requestEvent,
                Errata erratum,
                String productName,
                String productVersion,
                String toolVersion,
                SbomGenerationRequest releaseGeneration,
                Bom bom,
                List<Sbom> sboms) {

            validateComponent(
                    bom.getMetadata().getComponent(),
                    Component.Type.FRAMEWORK,
                    null,
                    "Red Hat build of Quarkus",
                    "Red Hat build of Quarkus 2.13.9.SP2",
                    "Red Hat build of Quarkus 2.13.9.SP2",
                    null,
                    List.of("cpe:/a:redhat:quarkus:2.13"),
                    Field.CPE);

            assertEquals(1, sboms.size());
            Bom manifestBom = SbomUtils.fromJsonNode(sboms.get(0).getSbom());
            String expectedPurl = SbomUtils.addQualifiersToPurlOfComponent(
                    manifestBom.getComponents().get(0),
                    Map.of("repository_url", Constants.MRRC_URL),
                    true);

            validateComponent(
                    bom.getComponents().get(0),
                    Component.Type.LIBRARY,
                    "com.redhat.quarkus.platform",
                    "quarkus-bom",
                    "2.13.9.SP2-redhat-00003",
                    "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@2.13.9.SP2-redhat-00003?type=pom",
                    "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@2.13.9.SP2-redhat-00003?type=pom",
                    List.of(expectedPurl),
                    Field.PURL);

            validateDependencies(
                    bom.getDependencies(),
                    1,
                    "Red Hat build of Quarkus 2.13.9.SP2",
                    List.of("pkg:maven/com.redhat.quarkus.platform/quarkus-bom@2.13.9.SP2-redhat-00003?type=pom"));
            validateProperty(
                    bom.getMetadata().getProperties(),
                    Constants.CONTAINER_PROPERTY_ADVISORY_ID,
                    String.valueOf(erratum.getDetails().get().getId()));

            printRawBom(bom);

            Sbom sbom = Sbom.builder()
                    .withIdentifier(releaseGeneration.getIdentifier())
                    .withSbom(SbomUtils.toJsonNode(bom))
                    .withGenerationRequest(releaseGeneration)
                    .withConfigIndex(0)
                    .build();

            // Add more information for this release so to find manifests more easily
            ObjectNode metadataNode = collectReleaseInfo(
                    requestEvent.getId(),
                    erratum,
                    productName,
                    productVersion,
                    bom);
            sbom.setReleaseMetadata(metadataNode);

            assertEquals(
                    "69436F788E634CB",
                    metadataNode.get(ReleaseStandardAdvisoryEventsListener.REQUEST_ID).asText());
            assertEquals("RHSA-2024:1797-02", metadataNode.get(ReleaseStandardAdvisoryEventsListener.ERRATA).asText());
            assertEquals("130278", metadataNode.get(ReleaseStandardAdvisoryEventsListener.ERRATA_ID).asText());
            assertEquals(
                    "Red Hat build of Quarkus",
                    metadataNode.get(ReleaseStandardAdvisoryEventsListener.PRODUCT).asText());
            assertEquals("RHBQ", metadataNode.get(ReleaseStandardAdvisoryEventsListener.PRODUCT_SHORTNAME).asText());
            assertEquals(
                    "Red Hat build of Quarkus 2.13.9.SP2",
                    metadataNode.get(ReleaseStandardAdvisoryEventsListener.PRODUCT_VERSION).asText());

            ArrayNode arrayNode = (ArrayNode) metadataNode.get(ReleaseStandardAdvisoryEventsListener.PURL_LIST);
            List<String> allPurls = List.of(
                    "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@2.13.9.SP2-redhat-00003?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=pom",
                    "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@2.13.9.SP2-redhat-00003?type=pom");

            for (int i = 0; i < arrayNode.size(); i++) {
                JsonNode node = arrayNode.get(i);
                assertEquals(node.asText(), allPurls.get(i));
            }
            return List.of(sbom);
        }
    }

    static class ReleaseTextOnlyAdvisoryEventsListenerDeliverables extends ReleaseTextOnlyAdvisoryEventsListener {
        @Override
        protected List<Sbom> saveReleaseManifestForTextOnlyAdvisories(
                RequestEvent requestEvent,
                Errata erratum,
                String productName,
                String productVersion,
                String toolVersion,
                SbomGenerationRequest releaseGeneration,
                Bom bom,
                List<Sbom> sboms) {

            validateComponent(
                    bom.getMetadata().getComponent(),
                    Component.Type.FRAMEWORK,
                    null,
                    "Red Hat build of Quarkus",
                    "Red Hat build of Quarkus 3.2.11",
                    "Red Hat build of Quarkus 3.2.11",
                    null,
                    List.of("cpe:/a:redhat:quarkus:3.2::el8"),
                    Field.CPE);

            // Verify that all the sboms are represented inside the release manifest
            assertEquals(2, sboms.size());
            assertEquals(2, bom.getComponents().size());
            validateProperty(
                    bom.getMetadata().getProperties(),
                    Constants.CONTAINER_PROPERTY_ADVISORY_ID,
                    String.valueOf(erratum.getDetails().get().getId()));

            Bom buildManifestBom = SbomUtils.fromJsonNode(sboms.get(0).getSbom());
            String buildExpectedPurl = SbomUtils.addQualifiersToPurlOfComponent(
                    buildManifestBom.getComponents().get(0),
                    Map.of("repository_url", Constants.MRRC_URL),
                    true);
            validateComponent(
                    bom.getComponents().get(0),
                    Component.Type.LIBRARY,
                    "com.redhat.quarkus.platform",
                    "quarkus-bom",
                    "3.2.11.Final-redhat-00001",
                    "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?type=pom",
                    "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?type=pom",
                    List.of(buildExpectedPurl),
                    Field.PURL);

            Bom operationManifestBom = SbomUtils.fromJsonNode(sboms.get(1).getSbom());
            String operationExpectedPurl = SbomUtils.addQualifiersToPurlOfComponent(
                    operationManifestBom.getMetadata().getComponent(),
                    Map.of("repository_url", Constants.MRRC_URL),
                    false);

            GenericPurlWrapperUtil gp = null;
            try {
                gp = new GenericPurlWrapperUtil(operationExpectedPurl);
            } catch (MalformedPackageURLException e) {
                fail("Failed to create GenericPurlWrapperUtil");
            }
            String operationExpectedPurlVersioned = gp.getVersionedPurl().canonicalize();
            validateComponent(
                    bom.getComponents().get(1),
                    Component.Type.FILE,
                    null,
                    "jboss-unified-push-1.0.0.Beta1-maven-repository.zip",
                    "sha256:1c2a89f755d5fdddef08c9f6f3b89e1e15cfa6d316055327bfe3f806acdbfca1",
                    "pkg:generic/jboss-unified-push-1.0.0.Beta1-maven-repository.zip?checksum=sha256%3A1c2a89f755d5fdddef08c9f6f3b89e1e15cfa6d316055327bfe3f806acdbfca1",
                    "pkg:generic/jboss-unified-push-1.0.0.Beta1-maven-repository.zip?checksum=sha256%3A1c2a89f755d5fdddef08c9f6f3b89e1e15cfa6d316055327bfe3f806acdbfca1",
                    List.of(operationExpectedPurl, operationExpectedPurlVersioned),
                    Field.PURL);

            validateDependencies(
                    bom.getDependencies(),
                    1,
                    "Red Hat build of Quarkus 3.2.11",
                    List.of(
                            "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?type=pom",
                            "pkg:generic/jboss-unified-push-1.0.0.Beta1-maven-repository.zip?checksum=sha256%3A1c2a89f755d5fdddef08c9f6f3b89e1e15cfa6d316055327bfe3f806acdbfca1"));

            printRawBom(bom);

            Sbom sbom = Sbom.builder()
                    .withIdentifier(releaseGeneration.getIdentifier())
                    .withSbom(SbomUtils.toJsonNode(bom))
                    .withGenerationRequest(releaseGeneration)
                    .withConfigIndex(0)
                    .build();

            // Add more information for this release so to find manifests more easily
            ObjectNode metadataNode = collectReleaseInfo(
                    requestEvent.getId(),
                    erratum,
                    productName,
                    productVersion,
                    bom);
            sbom.setReleaseMetadata(metadataNode);

            assertEquals(
                    "12747AFC7413496",
                    metadataNode.get(ReleaseStandardAdvisoryEventsListener.REQUEST_ID).asText());
            assertEquals("RHSA-2024:1662-01", metadataNode.get(ReleaseStandardAdvisoryEventsListener.ERRATA).asText());
            assertEquals("129589", metadataNode.get(ReleaseStandardAdvisoryEventsListener.ERRATA_ID).asText());
            assertEquals(
                    "Red Hat build of Quarkus",
                    metadataNode.get(ReleaseStandardAdvisoryEventsListener.PRODUCT).asText());
            assertEquals("RHBQ", metadataNode.get(ReleaseStandardAdvisoryEventsListener.PRODUCT_SHORTNAME).asText());
            assertEquals(
                    "Red Hat build of Quarkus 3.2.11",
                    metadataNode.get(ReleaseStandardAdvisoryEventsListener.PRODUCT_VERSION).asText());

            ArrayNode arrayNode = (ArrayNode) metadataNode.get(ReleaseStandardAdvisoryEventsListener.PURL_LIST);
            List<String> allPurls = List.of(
                    "pkg:generic/jboss-unified-push-1.0.0.Beta1-maven-repository.zip?checksum=sha256%3A1c2a89f755d5fdddef08c9f6f3b89e1e15cfa6d316055327bfe3f806acdbfca1",
                    "pkg:generic/jboss-unified-push-1.0.0.Beta1-maven-repository.zip?checksum=sha256%3A1c2a89f755d5fdddef08c9f6f3b89e1e15cfa6d316055327bfe3f806acdbfca1&repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F",
                    "pkg:generic/jboss-unified-push-eta1-maven-repository.zip@1.0.0.B?checksum=sha256%3A1c2a89f755d5fdddef08c9f6f3b89e1e15cfa6d316055327bfe3f806acdbfca1&repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F",
                    "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F&type=pom",
                    "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?type=pom");

            for (int i = 0; i < arrayNode.size(); i++) {
                JsonNode node = arrayNode.get(i);
                assertEquals(node.asText(), allPurls.get(i));
            }
            printRawBom(bom);

            // for each build manifest component in componets[], test component adjustment
            for (Sbom buildSbom : sboms) {
                Bom manifestBom = SbomUtils.fromJsonNode(buildSbom.getSbom());
                for (Component component : manifestBom.getComponents()) {
                    adjustComponent(component);
                }
            }

            return List.of(sbom);
        }
    }

    @Test
    void testTextOnlyReleaseErrataWithManifests() throws IOException {
        listenerTextOnlyManifests = new ReleaseTextOnlyAdvisoryEventsListenerManifests();
        listenerTextOnlyManifests.setErrataClient(errataClient);
        listenerTextOnlyManifests.setStatsService(statsService);
        listenerTextOnlyManifests.setSbomService(sbomService);
        listenerTextOnlyManifests.setGenerationRequestRepository(generationRequestRepository);
        listenerTextOnlyManifests.setRequestEventRepository(requestEventRepository);
        listenerTextOnlyManifests.setAtlasHandler(atlasHandler);

        String cpeText = "cpe:/a:redhat:quarkus:2.13";
        Errata errata = loadErrata("textOnly/manifests/errata.json");
        RequestEvent requestEvent = loadRequestEvent("textOnly/manifests/request_event.json");
        Sbom sbom = loadSbom("textOnly/manifests/6346322A131A437.json");

        Map<String, SbomGenerationRequest> pvToGenerations = new HashMap<>();
        Map<String, SbomGenerationRequest> generationsMap = new HashMap<>();
        assertTrue(errata.getDetails().isPresent());
        SbomGenerationRequest sbomGenerationRequest = SbomGenerationRequest.builder()
                .withId(RandomStringIdGenerator.generate())
                .withIdentifier(errata.getDetails().get().getFulladvisory() + "#" + cpeText)
                .withType(GenerationRequestType.BUILD)
                .withStatus(SbomGenerationStatus.GENERATING)
                .withConfig(null) // I really don't know what to put here
                .withRequest(requestEvent)
                .build();
        generationsMap.put(sbomGenerationRequest.getId(), sbomGenerationRequest);
        pvToGenerations.put(cpeText, sbomGenerationRequest);

        when(errataClient.getErratum(String.valueOf(errata.getDetails().get().getId()))).thenReturn(errata);
        when(statsService.getStats())
                .thenReturn(Stats.builder().withVersion("ReleaseAdvisoryEventsListenerTest_1.0.0").build());
        when(generationRequestRepository.findById(anyString())).thenAnswer(invocation -> {
            String generationId = invocation.getArgument(0);
            return generationsMap.get(generationId);
        });
        when(requestEventRepository.findById(anyString())).thenReturn(requestEvent);
        String purlRef = "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@2.13.9.SP2-redhat-00003?repository_url=https://maven.repository.redhat.com/ga/&type=pom";
        when(sbomService.findByPurl(purlRef)).thenReturn(sbom);

        TextOnlyAdvisoryReleaseEvent event = TextOnlyAdvisoryReleaseEvent.builder()
                .withRequestEventId(requestEvent.getId())
                .withReleaseGenerations(pvToGenerations)
                .build();
        MdcEventWrapper wrapper = new MdcEventWrapper(event, MDC.getCopyOfContextMap());

        listenerTextOnlyManifests.onReleaseAdvisoryEvent(wrapper);
        event.getReleaseGenerations()
                .values()
                .forEach(request -> assertNotEquals(RequestEventStatus.FAILED, request.getRequest().getEventStatus()));
    }

    @Test
    void testTextOnlyReleaseErrataWithDeliverables() throws IOException {
        listenerTextOnlyDeliverables = new ReleaseTextOnlyAdvisoryEventsListenerDeliverables();
        listenerTextOnlyDeliverables.setErrataClient(errataClient);
        listenerTextOnlyDeliverables.setStatsService(statsService);
        listenerTextOnlyDeliverables.setSbomService(sbomService);
        listenerTextOnlyDeliverables.setGenerationRequestRepository(generationRequestRepository);
        listenerTextOnlyDeliverables.setRequestEventRepository(requestEventRepository);
        listenerTextOnlyDeliverables.setAtlasHandler(atlasHandler);

        String cpeText = "cpe:/a:redhat:quarkus:3.2::el8";
        Errata errata = loadErrata("textOnly/deliverables/errata.json");
        RequestEvent requestEvent = loadRequestEvent("textOnly/deliverables/request_event.json");
        List<V1Beta1RequestRecord> allAdvisoryRequestRecords = loadRequestRecords(
                "textOnly/deliverables/errata_records.json");

        Sbom pncBuildSbom = loadSbom("textOnly/deliverables/E03673C8D82E484.json");
        Sbom operationSbom = loadSbom("textOnly/deliverables/A8342BD50FB9496.json");

        Map<String, SbomGenerationRequest> pvToGenerations = new HashMap<>();
        Map<String, SbomGenerationRequest> generationsMap = new HashMap<>();
        assertTrue(errata.getDetails().isPresent());
        SbomGenerationRequest sbomGenerationRequest = SbomGenerationRequest.builder()
                .withId(RandomStringIdGenerator.generate())
                .withIdentifier(errata.getDetails().get().getFulladvisory() + "#" + cpeText)
                .withType(GenerationRequestType.BUILD)
                .withStatus(SbomGenerationStatus.GENERATING)
                .withConfig(null) // I really don't know what to put here
                .withRequest(requestEvent)
                .build();
        generationsMap.put(sbomGenerationRequest.getId(), sbomGenerationRequest);
        pvToGenerations.put(cpeText, sbomGenerationRequest);

        when(errataClient.getErratum(String.valueOf(errata.getDetails().get().getId()))).thenReturn(errata);
        when(statsService.getStats())
                .thenReturn(Stats.builder().withVersion("ReleaseAdvisoryEventsListenerTest_1.0.0").build());
        when(generationRequestRepository.findById(anyString())).thenAnswer(invocation -> {
            String generationId = invocation.getArgument(0);
            return generationsMap.get(generationId);
        });
        when(requestEventRepository.findById(anyString())).thenReturn(requestEvent);
        when(sbomService.searchLastSuccessfulAdvisoryBuildRequestRecord(anyString(), anyString()))
                .thenReturn(allAdvisoryRequestRecords.get(0));

        String pncBuildUrl = "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?type=pom";
        String operationUrl = "pkg:generic/jboss-unified-push-1.0.0.Beta1-maven-repository.zip?checksum=sha256%3A1c2a89f755d5fdddef08c9f6f3b89e1e15cfa6d316055327bfe3f806acdbfca1";
        when(sbomService.findByPurl(pncBuildUrl)).thenReturn(pncBuildSbom);
        when(sbomService.findByPurl(operationUrl)).thenReturn(operationSbom);

        TextOnlyAdvisoryReleaseEvent event = TextOnlyAdvisoryReleaseEvent.builder()
                .withRequestEventId(requestEvent.getId())
                .withReleaseGenerations(pvToGenerations)
                .build();
        MdcEventWrapper wrapper = new MdcEventWrapper(event, MDC.getCopyOfContextMap());

        listenerTextOnlyDeliverables.onReleaseAdvisoryEvent(wrapper);
        event.getReleaseGenerations()
                .values()
                .forEach(request -> assertNotEquals(RequestEventStatus.FAILED, request.getRequest().getEventStatus()));
    }

    @Test
    void testReleaseErrataWithSingleDockerBuild() throws IOException {
        listenerSingleContainer = new ReleaseAdvisoryEventsListenerSingleContainer();
        listenerSingleContainer.setErrataClient(errataClient);
        listenerSingleContainer.setPyxisClient(pyxisClient);
        listenerSingleContainer.setStatsService(statsService);
        listenerSingleContainer.setSbomService(sbomService);
        listenerSingleContainer.setGenerationRequestRepository(generationRequestRepository);
        listenerSingleContainer.setRequestEventRepository(requestEventRepository);
        listenerSingleContainer.setAtlasHandler(atlasHandler);

        // Get all objects required
        Errata errata = loadErrata("singleContainer/errata_143793.json");
        ErrataBuildList erratumBuildList = loadErrataBuildList("singleContainer/errata_143793_build_list.json");
        ErrataVariant variant = loadErrataVariant("singleContainer/errata_143793_variant.json");
        List<V1Beta1RequestRecord> allAdvisoryRequestRecords = loadRequestRecords(
                "singleContainer/errata_143793_records.json");
        RequestEvent requestEvent = loadRequestEvent("singleContainer/request_event.json");
        Sbom firstManifest = loadSbom("singleContainer/A14FF4DDB7DB47D.json");
        Sbom indexManifest = loadSbom("singleContainer/2A5F7CA4166C470.json");
        PyxisRepositoryDetails repositoriesDetails = loadPyxisRepositoryDetails("singleContainer/pyxis.json");

        Map<ProductVersionEntry, List<BuildItem>> buildDetails = erratumBuildList.getProductVersions()
                .values()
                .stream()
                .collect(
                        Collectors.toMap(
                                productVersionEntry -> productVersionEntry,
                                productVersionEntry -> productVersionEntry.getBuilds()
                                        .stream()
                                        .flatMap(build -> build.getBuildItems().values().stream())
                                        .toList()));

        V1Beta1RequestRecord latestAdvisoryRequestManifest = allAdvisoryRequestRecords.get(0);
        Map<String, SbomGenerationRequest> pvToGenerations = new HashMap<>();
        Map<String, SbomGenerationRequest> generationsMap = new HashMap<>();

        buildDetails.keySet().forEach(pv -> {
            String generationId = RandomStringIdGenerator.generate();
            assertTrue(errata.getDetails().isPresent());
            SbomGenerationRequest sbomGenerationRequest = SbomGenerationRequest.builder()
                    .withId(generationId)
                    .withIdentifier(errata.getDetails().get().getFulladvisory() + "#" + pv.getName())
                    .withType(GenerationRequestType.CONTAINERIMAGE)
                    .withStatus(SbomGenerationStatus.GENERATING)
                    .withConfig(null) // I really don't know what to put here
                    .withRequest(requestEvent)
                    .build();

            generationsMap.put(generationId, sbomGenerationRequest);
            pvToGenerations.put(pv.getName(), sbomGenerationRequest);
        });
        when(errataClient.getVariant("AppStream-8.10.0.Z.MAIN.EUS")).thenReturn(variant);
        when(errataClient.getBuildsList(String.valueOf(errata.getDetails().get().getId())))
                .thenReturn(erratumBuildList);
        when(errataClient.getErratum(String.valueOf(errata.getDetails().get().getId()))).thenReturn(errata);

        when(statsService.getStats())
                .thenReturn(Stats.builder().withVersion("ReleaseAdvisoryEventsListenerTest_1.0.0").build());

        when(pyxisClient.getRepositoriesDetails(anyString(), anyList())).thenReturn(repositoriesDetails);

        when(generationRequestRepository.findById(anyString())).thenAnswer(invocation -> {
            String generationId = invocation.getArgument(0);
            return generationsMap.get(generationId);
        });
        when(requestEventRepository.findById(anyString())).thenReturn(requestEvent);

        when(sbomService.get("A14FF4DDB7DB47D")).thenReturn(firstManifest);
        when(sbomService.get("2A5F7CA4166C470")).thenReturn(indexManifest);
        when(sbomService.save(any(Sbom.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(sbomService.searchLastSuccessfulAdvisoryBuildRequestRecord(anyString(), anyString()))
                .thenReturn(latestAdvisoryRequestManifest);

        StandardAdvisoryReleaseEvent event = StandardAdvisoryReleaseEvent.builder()
                .withRequestEventId(requestEvent.getId())
                .withReleaseGenerations(pvToGenerations)
                .build();
        MdcEventWrapper wrapper = new MdcEventWrapper(event, MDC.getCopyOfContextMap());

        listenerSingleContainer.onReleaseAdvisoryEvent(wrapper);
        event.getReleaseGenerations()
                .values()
                .forEach(request -> assertNotEquals(RequestEventStatus.FAILED, request.getRequest().getEventStatus()));
    }

    @Test
    void testReleaseErrataWithMultiDockerBuilds() throws IOException {
        listenerMultiContainers = new ReleaseAdvisoryEventsListenerMultiContainer();
        listenerMultiContainers.setErrataClient(errataClient);
        listenerMultiContainers.setPyxisClient(pyxisClient);
        listenerMultiContainers.setStatsService(statsService);
        listenerMultiContainers.setSbomService(sbomService);
        listenerMultiContainers.setGenerationRequestRepository(generationRequestRepository);
        listenerMultiContainers.setRequestEventRepository(requestEventRepository);
        listenerMultiContainers.setAtlasHandler(atlasHandler);

        // Get all objects required
        //
        Map<String, PyxisRepositoryDetails> pyxisRepositories = new HashMap<>();
        pyxisRepositories.put(
                "ose-clusterresourceoverride-operator-metadata-container-v4.15.0.202412021736.p0.g40c168c.assembly.stream.el9-1",
                loadPyxisRepositoryDetails("multiContainers/pyxis_3421076.json"));
        pyxisRepositories.put(
                "ose-vertical-pod-autoscaler-operator-metadata-container-v4.15.0.202412021736.p0.g8876256.assembly.stream.el9-1",
                loadPyxisRepositoryDetails("multiContainers/pyxis_3421077.json"));
        pyxisRepositories.put(
                "cluster-nfd-operator-metadata-container-v4.15.0.202412041605.p0.gabdfb61.assembly.stream.el9-2",
                loadPyxisRepositoryDetails("multiContainers/pyxis_3427588.json"));
        pyxisRepositories.put(
                "ingress-node-firewall-operator-bundle-container-v4.15.0.202412041605.p0.g135f832.assembly.stream.el9-2",
                loadPyxisRepositoryDetails("multiContainers/pyxis_3427589.json"));
        pyxisRepositories.put(
                "local-storage-operator-metadata-container-v4.15.0.202412041605.p0.gcc4f213.assembly.stream.el9-2",
                loadPyxisRepositoryDetails("multiContainers/pyxis_3427592.json"));
        pyxisRepositories.put(
                "ose-metallb-operator-bundle-container-v4.15.0.202412041605.p0.g359620b.assembly.stream.el9-2",
                loadPyxisRepositoryDetails("multiContainers/pyxis_3427593.json"));
        pyxisRepositories.put(
                "ose-kubernetes-nmstate-operator-bundle-container-v4.15.0.202412041605.p0.g0d290b4.assembly.stream.el9-2",
                loadPyxisRepositoryDetails("multiContainers/pyxis_3427594.json"));
        pyxisRepositories.put(
                "ose-ptp-operator-metadata-container-v4.15.0.202412041605.p0.g6fb51fd.assembly.stream.el9-2",
                loadPyxisRepositoryDetails("multiContainers/pyxis_3427595.json"));
        pyxisRepositories.put(
                "ose-gcp-filestore-csi-driver-operator-bundle-container-v4.15.0.202412041605.p0.ga923e95.assembly.stream.el8-2",
                loadPyxisRepositoryDetails("multiContainers/pyxis_3427596.json"));
        pyxisRepositories.put(
                "ose-aws-efs-csi-driver-operator-bundle-container-v4.15.0.202412041605.p0.gb0f13a0.assembly.stream.el8-2",
                loadPyxisRepositoryDetails("multiContainers/pyxis_3427616.json"));
        pyxisRepositories.put(
                "ose-secrets-store-csi-driver-operator-bundle-container-v4.15.0.202412041605.p0.gef602a5.assembly.stream.el8-2",
                loadPyxisRepositoryDetails("multiContainers/pyxis_3427615.json"));

        Errata errata = loadErrata("multiContainers/errata_143781.json");
        ErrataBuildList erratumBuildList = loadErrataBuildList("multiContainers/errata_143781_build_list.json");
        List<V1Beta1RequestRecord> allAdvisoryRequestRecords = loadRequestRecords(
                "multiContainers/errata_143781_records.json");
        RequestEvent requestEvent = loadRequestEvent("multiContainers/request_event.json");

        Map<String, Sbom> sboms = new HashMap<>();
        sboms.put("505A5B90871046D", loadSbom("multiContainers/505A5B90871046D.json"));
        sboms.put("415DE22239C9439", loadSbom("multiContainers/415DE22239C9439.json"));
        sboms.put("47F4BC6A1C1641B", loadSbom("multiContainers/47F4BC6A1C1641B.json"));
        sboms.put("972A7D1C755548A", loadSbom("multiContainers/972A7D1C755548A.json"));
        sboms.put("8FEBABB08A614E6", loadSbom("multiContainers/8FEBABB08A614E6.json"));
        sboms.put("D8820BD0227F430", loadSbom("multiContainers/D8820BD0227F430.json"));
        sboms.put("2B7738D0D6964CB", loadSbom("multiContainers/2B7738D0D6964CB.json"));
        sboms.put("96D539F40D73483", loadSbom("multiContainers/96D539F40D73483.json"));
        sboms.put("1251FF8155D74B5", loadSbom("multiContainers/1251FF8155D74B5.json"));
        sboms.put("CDCBA3AA014747E", loadSbom("multiContainers/CDCBA3AA014747E.json"));
        sboms.put("AB81F89CF06645A", loadSbom("multiContainers/AB81F89CF06645A.json"));
        sboms.put("6AC3057851CB480", loadSbom("multiContainers/6AC3057851CB480.json"));
        sboms.put("9598ACF8368F49E", loadSbom("multiContainers/9598ACF8368F49E.json"));
        sboms.put("C67D863805F6463", loadSbom("multiContainers/C67D863805F6463.json"));
        sboms.put("EAABD415A3C7420", loadSbom("multiContainers/EAABD415A3C7420.json"));
        sboms.put("1DEFC26D4700433", loadSbom("multiContainers/1DEFC26D4700433.json"));
        sboms.put("FD64B2D3C6484CF", loadSbom("multiContainers/FD64B2D3C6484CF.json"));
        sboms.put("E0527227ABA94B9", loadSbom("multiContainers/E0527227ABA94B9.json"));
        sboms.put("0B7A5E98F9CE46E", loadSbom("multiContainers/0B7A5E98F9CE46E.json"));
        sboms.put("5095B5376819410", loadSbom("multiContainers/5095B5376819410.json"));
        sboms.put("3192918668C2431", loadSbom("multiContainers/3192918668C2431.json"));
        sboms.put("DC8F6347901E470", loadSbom("multiContainers/DC8F6347901E470.json"));

        ErrataVariant variant8BaseRHOSE415 = loadErrataVariant(
                "multiContainers/errata_143781_variant_8Base-RHOSE-4.15.json");
        ErrataVariant variant9BaseRHOSE415 = loadErrataVariant(
                "multiContainers/errata_143781_variant_9Base-RHOSE-4.15.json");

        Map<ProductVersionEntry, List<BuildItem>> buildDetails = erratumBuildList.getProductVersions()
                .values()
                .stream()
                .collect(
                        Collectors.toMap(
                                productVersionEntry -> productVersionEntry,
                                productVersionEntry -> productVersionEntry.getBuilds()
                                        .stream()
                                        .flatMap(build -> build.getBuildItems().values().stream())
                                        .toList()));

        V1Beta1RequestRecord latestAdvisoryRequestManifest = allAdvisoryRequestRecords.get(0);
        Map<String, SbomGenerationRequest> pvToGenerations = new HashMap<>();
        Map<String, SbomGenerationRequest> generationsMap = new HashMap<>();

        buildDetails.keySet().forEach(pv -> {
            String generationId = RandomStringIdGenerator.generate();
            assertTrue(errata.getDetails().isPresent());
            SbomGenerationRequest sbomGenerationRequest = SbomGenerationRequest.builder()
                    .withId(generationId)
                    .withIdentifier(errata.getDetails().get().getFulladvisory() + "#" + pv.getName())
                    .withType(GenerationRequestType.CONTAINERIMAGE)
                    .withStatus(SbomGenerationStatus.GENERATING)
                    .withConfig(null) // I really don't know what to put here
                    .withRequest(requestEvent)
                    .build();

            generationsMap.put(generationId, sbomGenerationRequest);
            pvToGenerations.put(pv.getName(), sbomGenerationRequest);
        });

        when(errataClient.getVariant("8Base-RHOSE-4.15")).thenReturn(variant8BaseRHOSE415);
        when(errataClient.getVariant("9Base-RHOSE-4.15")).thenReturn(variant9BaseRHOSE415);
        when(errataClient.getBuildsList(String.valueOf(errata.getDetails().get().getId())))
                .thenReturn(erratumBuildList);
        when(errataClient.getErratum(String.valueOf(errata.getDetails().get().getId()))).thenReturn(errata);

        when(statsService.getStats())
                .thenReturn(Stats.builder().withVersion("ReleaseAdvisoryEventsListenerTest_1.0.0").build());

        when(pyxisClient.getRepositoriesDetails(anyString(), anyList()))
                .thenAnswer(invocation -> pyxisRepositories.get(invocation.getArgument(0)));

        when(generationRequestRepository.findById(anyString())).thenAnswer(invocation -> {
            String generationId = invocation.getArgument(0);
            return generationsMap.get(generationId);
        });
        when(requestEventRepository.findById(anyString())).thenReturn(requestEvent);

        when(sbomService.get(anyString())).thenAnswer(invocation -> sboms.get(invocation.getArgument(0)));
        when(sbomService.save(any(Sbom.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(sbomService.searchLastSuccessfulAdvisoryBuildRequestRecord(anyString(), anyString()))
                .thenReturn(latestAdvisoryRequestManifest);

        StandardAdvisoryReleaseEvent event = StandardAdvisoryReleaseEvent.builder()
                .withRequestEventId(requestEvent.getId())
                .withReleaseGenerations(pvToGenerations)
                .build();
        MdcEventWrapper wrapper = new MdcEventWrapper(event, MDC.getCopyOfContextMap());
        listenerMultiContainers.onReleaseAdvisoryEvent(wrapper);
        event.getReleaseGenerations()
                .values()
                .forEach(request -> assertNotEquals(RequestEventStatus.FAILED, request.getRequest().getEventStatus()));
    }

    @Test
    void testReleaseErrataWithSingleRPMBuild() throws IOException {
        listenerSingleRpm = new ReleaseAdvisoryEventsListenerSingleRPM();
        listenerSingleRpm.setErrataClient(errataClient);
        listenerSingleRpm.setPyxisClient(pyxisClient);
        listenerSingleRpm.setStatsService(statsService);
        listenerSingleRpm.setSbomService(sbomService);
        listenerSingleRpm.setGenerationRequestRepository(generationRequestRepository);
        listenerSingleRpm.setRequestEventRepository(requestEventRepository);
        listenerSingleRpm.setAtlasHandler(atlasHandler);

        // Get all objects required
        Errata errata = loadErrata("singleRpm/errata_89769.json");
        ErrataBuildList erratumBuildList = loadErrataBuildList("singleRpm/errata_89769_build_list.json");
        ErrataVariant variant = loadErrataVariant("singleRpm/errata_89769_variant.json");
        List<V1Beta1RequestRecord> allAdvisoryRequestRecords = loadRequestRecords(
                "singleRpm/errata_89769_records.json");
        RequestEvent requestEvent = loadRequestEvent("singleRpm/request_event.json");
        Sbom manifest = loadSbom("singleRpm/356D95E8FF434C4.json");
        List<ErrataCDNRepoNormalized> cdnRepos = loadCDNReposDetails(
                "singleRpm/cdn_repos.json",
                "7ComputeNode-7.2.Z",
                "RHEL");

        Map<ProductVersionEntry, List<BuildItem>> buildDetails = erratumBuildList.getProductVersions()
                .values()
                .stream()
                .collect(
                        Collectors.toMap(
                                productVersionEntry -> productVersionEntry,
                                productVersionEntry -> productVersionEntry.getBuilds()
                                        .stream()
                                        .flatMap(build -> build.getBuildItems().values().stream())
                                        .toList()));

        V1Beta1RequestRecord latestAdvisoryRequestManifest = allAdvisoryRequestRecords.get(0);
        Map<String, SbomGenerationRequest> pvToGenerations = new HashMap<>();
        Map<String, SbomGenerationRequest> generationsMap = new HashMap<>();

        buildDetails.keySet().forEach(pv -> {
            String generationId = RandomStringIdGenerator.generate();
            assertTrue(errata.getDetails().isPresent());
            SbomGenerationRequest sbomGenerationRequest = SbomGenerationRequest.builder()
                    .withId(generationId)
                    .withIdentifier(errata.getDetails().get().getFulladvisory() + "#" + pv.getName())
                    .withType(GenerationRequestType.BREW_RPM)
                    .withStatus(SbomGenerationStatus.GENERATING)
                    .withConfig(null) // I really don't know what to put here
                    .withRequest(requestEvent)
                    .build();

            generationsMap.put(generationId, sbomGenerationRequest);
            pvToGenerations.put(pv.getName(), sbomGenerationRequest);
        });
        when(errataClient.getVariant("7ComputeNode-7.2.Z")).thenReturn(variant);
        assertTrue(errata.getDetails().isPresent());
        when(errataClient.getBuildsList(String.valueOf(errata.getDetails().get().getId())))
                .thenReturn(erratumBuildList);
        when(errataClient.getErratum(String.valueOf(errata.getDetails().get().getId()))).thenReturn(errata);

        when(statsService.getStats())
                .thenReturn(Stats.builder().withVersion("ReleaseAdvisoryEventsListenerTest_1.0.0").build());

        when(errataClient.getCDNReposOfVariant("7ComputeNode-7.2.Z", "RHEL")).thenReturn(cdnRepos);

        when(generationRequestRepository.findById(anyString())).thenAnswer(invocation -> {
            String generationId = invocation.getArgument(0);
            return generationsMap.get(generationId);
        });
        when(requestEventRepository.findById(anyString())).thenReturn(requestEvent);

        when(sbomService.get("356D95E8FF434C4")).thenReturn(manifest);
        when(sbomService.save(any(Sbom.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(sbomService.searchLastSuccessfulAdvisoryBuildRequestRecord(anyString(), anyString()))
                .thenReturn(latestAdvisoryRequestManifest);

        StandardAdvisoryReleaseEvent event = StandardAdvisoryReleaseEvent.builder()
                .withRequestEventId(requestEvent.getId())
                .withReleaseGenerations(pvToGenerations)
                .build();
        MdcEventWrapper wrapper = new MdcEventWrapper(event, MDC.getCopyOfContextMap());
        listenerSingleRpm.onReleaseAdvisoryEvent(wrapper);
        event.getReleaseGenerations()
                .values()
                .forEach(request -> assertNotEquals(RequestEventStatus.FAILED, request.getRequest().getEventStatus()));
    }

    private List<ErrataCDNRepoNormalized> loadCDNReposDetails(
            String fileName,
            String variantName,
            String shortProductName) throws IOException {
        Collection<ErrataCDNRepo> cdnRepos = parseResource(fileName, new TypeReference<>() {
        });
        return cdnRepos.stream()
                .filter(
                        cdn -> cdn.getType().equals("cdn_repos")
                                && !cdn.getAttributes().getContentType().equalsIgnoreCase("docker"))
                .map(cdn -> new ErrataCDNRepoNormalized(cdn, variantName, !"rhel".equalsIgnoreCase(shortProductName)))
                .distinct()
                .toList();
    }

    private PyxisRepositoryDetails loadPyxisRepositoryDetails(String fileName) throws IOException {
        return parseResource(fileName, PyxisRepositoryDetails.class);
    }

    private Sbom loadSbom(String fileName) throws IOException {
        return parseResource(fileName, Sbom.class);
    }

    private Errata loadErrata(String fileName) throws IOException {
        return parseResource(fileName, Errata.class);
    }

    private ErrataVariant loadErrataVariant(String fileName) throws IOException {
        return parseResource(fileName, ErrataVariant.class);
    }

    private ErrataBuildList loadErrataBuildList(String fileName) throws IOException {
        return parseResource(fileName, ErrataBuildList.class);
    }

    private RequestEvent loadRequestEvent(String fileName) throws IOException {
        return parseResource(fileName, RequestEvent.class);
    }

    private List<V1Beta1RequestRecord> loadRequestRecords(String fileName) throws IOException {
        return parseResource(fileName, new TypeReference<>() {
        });
    }

    private <T> T parseResource(String fileName, Class<T> type) throws IOException {
        return ObjectMapperProvider.json().readValue(TestResources.asString("errata/release/" + fileName), type);
    }

    private <T> T parseResource(String fileName, TypeReference<T> typeReference) throws IOException {
        return ObjectMapperProvider.json()
                .readValue(TestResources.asString("errata/release/" + fileName), typeReference);
    }

}
