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
package org.jboss.sbomer.service.test.integ.feature.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.cyclonedx.model.Bom;
import org.jboss.sbomer.core.features.sbom.config.Config;
import org.jboss.sbomer.core.features.sbom.config.OperationConfig;
import org.jboss.sbomer.core.features.sbom.config.PncBuildConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.DefaultProcessorConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.ErrataConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.GeneratorConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.ProductConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.RedHatProductProcessorConfig;
import org.jboss.sbomer.core.features.sbom.enums.GenerationRequestType;
import org.jboss.sbomer.core.features.sbom.enums.GeneratorType;
import org.jboss.sbomer.core.features.sbom.rest.Page;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.service.feature.sbom.k8s.model.GenerationRequest;
import org.jboss.sbomer.service.feature.sbom.k8s.model.GenerationRequestBuilder;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationStatus;
import org.jboss.sbomer.service.feature.sbom.model.Sbom;
import org.jboss.sbomer.service.feature.sbom.model.SbomGenerationRequest;
import org.jboss.sbomer.service.feature.sbom.service.SbomGenerationRequestRepository;
import org.jboss.sbomer.service.feature.sbom.service.SbomRepository;
import org.jboss.sbomer.service.feature.sbom.service.SbomService;
import org.jboss.sbomer.service.rest.QueryParameters;
import org.jboss.sbomer.service.test.utils.QuarkusTransactionalTest;
import org.jboss.sbomer.service.test.utils.umb.TestUmbProfile;
import org.junit.jupiter.api.Test;

import io.quarkus.panache.common.Parameters;
import io.quarkus.test.junit.TestProfile;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.validation.Validator;

@ApplicationScoped
@QuarkusTransactionalTest
@TestProfile(TestUmbProfile.class)
class SbomGenerationRequestRepositoryTest {

    @Inject
    Validator validator;

    @Inject
    SbomRepository sbomRepository;

    @Inject
    SbomGenerationRequestRepository sbomGenerationRequestRepository;

    @Inject
    SbomService sbomService;

    static final String REQUEST_ID = "FFAASSBB";
    static final String OPERATION_REQUEST_ID = "OPFFAASSBB";
    static final String BUILD_ID = "RRYT3LBXDVYAC";
    static final String OPERATION_ID = "OPERATION13";

    static final String REQUEST_ID_2_DELETE = "FFAASSBBDD";
    static final String BUILD_ID_2_DELETE = "RRYT3LBXDVYACDD";

    static final String IMPORTED_REQUEST_ID = "AASSBB";

    static Path sbomPath(String fileName) {
        return Paths.get("src", "test", "resources", "sboms", fileName);
    }

    private Config createRuntimeConfig(String buildId) {
        GeneratorConfig generatorConfig = GeneratorConfig.builder()
                .type(GeneratorType.MAVEN_CYCLONEDX)
                .args("--include-non-managed --warn-on-missing-scm")
                .version("0.0.90")
                .build();

        DefaultProcessorConfig defaultProcessorConfig = DefaultProcessorConfig.builder().build();
        RedHatProductProcessorConfig redHatProductProcessorConfig = RedHatProductProcessorConfig.builder()
                .withErrata(
                        ErrataConfig.builder()
                                .productName("CCCDDD")
                                .productVersion("CCDD")
                                .productVariant("CD")
                                .build())
                .build();
        ProductConfig productConfig = ProductConfig.builder()
                .withGenerator(generatorConfig)
                .withProcessors(List.of(defaultProcessorConfig, redHatProductProcessorConfig))
                .build();

        return PncBuildConfig.builder()
                .withApiVersion("sbomer.jboss.org/v1alpha1")
                .withBuildId(buildId)
                .withProducts(List.of(productConfig))
                .withEnvironment(Map.of("k", "v"))
                .build();
    }

    private OperationConfig createRuntimeOperationConfig(String operationId) {
        GeneratorConfig generatorConfig = GeneratorConfig.builder().type(GeneratorType.CYCLONEDX_OPERATION).build();

        RedHatProductProcessorConfig redHatProductProcessorConfig = RedHatProductProcessorConfig.builder()
                .withErrata(
                        ErrataConfig.builder()
                                .productName("CCCDDD")
                                .productVersion("CCDD")
                                .productVariant("CD")
                                .build())
                .build();
        ProductConfig productConfig = ProductConfig.builder()
                .withGenerator(generatorConfig)
                .withProcessors(List.of(redHatProductProcessorConfig))
                .build();

        return OperationConfig.builder()
                .withApiVersion("sbomer.jboss.org/v1alpha1")
                .withOperationId(operationId)
                .withProduct(productConfig)
                .build();
    }

    private Sbom createSBOM() {
        Bom bom = SbomUtils.fromPath(sbomPath("complete_sbom.json"));
        Config runtimeConfig = createRuntimeConfig(BUILD_ID);

        SbomGenerationRequest generationRequest = SbomGenerationRequest.builder()
                .withConfig(runtimeConfig)
                .withId(REQUEST_ID)
                .withIdentifier(BUILD_ID)
                .withType(GenerationRequestType.BUILD)
                .withStatus(SbomGenerationStatus.FINISHED)
                .build();

        // Not setting rootPurl, as it will be set by PrePersist
        Sbom sbom = new Sbom();
        sbom.setIdentifier(BUILD_ID);
        sbom.setId("416640206274228333");
        sbom.setSbom(SbomUtils.toJsonNode(bom));
        sbom.setGenerationRequest(generationRequest);
        return sbom;
    }

    private Sbom createOperationSBOM() {
        Bom bom = SbomUtils.fromPath(sbomPath("complete_sbom.json"));
        OperationConfig runtimeConfig = createRuntimeOperationConfig(OPERATION_ID);

        SbomGenerationRequest generationRequest = SbomGenerationRequest.builder()
                .withConfig(runtimeConfig)
                .withId(OPERATION_REQUEST_ID)
                .withIdentifier(OPERATION_ID)
                .withType(GenerationRequestType.OPERATION)
                .withStatus(SbomGenerationStatus.FINISHED)
                .build();

        // Not setting rootPurl, as it will be set by PrePersist
        Sbom sbom = new Sbom();
        sbom.setIdentifier(OPERATION_ID);
        sbom.setId("131340206274228333");
        sbom.setSbom(SbomUtils.toJsonNode(bom));
        sbom.setGenerationRequest(generationRequest);
        return sbom;
    }

    @PostConstruct
    void init() {
        Sbom sbom = createSBOM();
        Sbom operationSbom = createOperationSBOM();
        sbomRepository.saveSbom(sbom);
        sbomRepository.saveSbom(operationSbom);
    }

    @Test
    void testRSQL() {
        SbomGenerationRequest request = sbomGenerationRequestRepository.search(
                QueryParameters.builder().rsqlQuery("identifier=eq=" + BUILD_ID).pageIndex(0).pageSize(1).build())
                .get(0);

        assertNotNull(request);
        assertNotNull(request.getCreationTime());
        assertEquals(REQUEST_ID, request.getId());
        assertEquals(GenerationRequestType.BUILD, request.getType());
        assertEquals(BUILD_ID, request.getIdentifier());

        request = sbomGenerationRequestRepository.search(
                QueryParameters.builder().rsqlQuery("identifier=eq=" + BUILD_ID).pageIndex(0).pageSize(1).build())
                .get(0);

        assertNotNull(request);
        assertEquals(REQUEST_ID, request.getId());
        assertEquals(BUILD_ID, request.getIdentifier());
        assertEquals(GenerationRequestType.BUILD, request.getType());
        assertEquals("FINISHED".toLowerCase(), request.getStatus().toName());

        request = sbomGenerationRequestRepository.search(
                QueryParameters.builder().rsqlQuery("identifier=eq=" + OPERATION_ID).pageIndex(0).pageSize(1).build())
                .get(0);

        assertNotNull(request);
        assertEquals(OPERATION_REQUEST_ID, request.getId());
        assertEquals(OPERATION_ID, request.getIdentifier());
        assertEquals(GenerationRequestType.OPERATION, request.getType());
        assertEquals("FINISHED".toLowerCase(), request.getStatus().toName());
    }

    @Test
    void testRSQLWithMultipleLikes() {
        List<SbomGenerationRequest> requests = sbomGenerationRequestRepository.search(
                QueryParameters.builder()
                        .rsqlQuery("reason=like=%it succeeded% and reason=like=%t succeede%")
                        .pageIndex(0)
                        .pageSize(10)
                        .build());
        assertEquals(1, requests.size());
        assertEquals(IMPORTED_REQUEST_ID, requests.get(0).getId());
        List<SbomGenerationRequest> requests2 = sbomGenerationRequestRepository.search(
                QueryParameters.builder()
                        .rsqlQuery("reason=like=%it succeeded% and reason=like=%other%")
                        .pageIndex(0)
                        .pageSize(10)
                        .build());
        assertTrue(requests2.isEmpty());
    }

    @Test
    void testPagination() {
        Page<SbomGenerationRequest> pagedRequest = sbomService
                .searchSbomRequestsByQueryPaginated(0, 10, "identifier=eq=" + BUILD_ID, null);

        assertNotNull(pagedRequest);
        assertEquals(0, pagedRequest.getPageIndex());
        assertEquals(10, pagedRequest.getPageSize());
        assertEquals(1, pagedRequest.getTotalHits());
        assertEquals(1, pagedRequest.getTotalPages());
        assertEquals(1, pagedRequest.getContent().size());
        SbomGenerationRequest request = pagedRequest.getContent().iterator().next();
        assertNotNull(request.getCreationTime());
        assertEquals(REQUEST_ID, request.getId());
        assertEquals(BUILD_ID, request.getIdentifier());
    }

    @Test
    void testFindByIdSbomGenerationRequest() {
        SbomGenerationRequest request = SbomGenerationRequest.findById(REQUEST_ID); // NOSONAR

        assertEquals(REQUEST_ID, request.getId());
        assertEquals(BUILD_ID, request.getIdentifier());
    }

    @Test
    void testFindByOperationIdSbomGenerationRequest() {
        SbomGenerationRequest request = SbomGenerationRequest.findById(OPERATION_REQUEST_ID); // NOSONAR

        assertEquals(OPERATION_REQUEST_ID, request.getId());
        assertEquals(OPERATION_ID, request.getIdentifier());
    }

    @Test
    void testDeleteSbomGenerationRequest() {
        Config runtimeConfig = createRuntimeConfig(BUILD_ID_2_DELETE);

        SbomGenerationRequest generationRequest = SbomGenerationRequest.builder()
                .withConfig(runtimeConfig)
                .withId(REQUEST_ID_2_DELETE)
                .withIdentifier(BUILD_ID_2_DELETE)
                .withType(GenerationRequestType.BUILD)
                .withStatus(SbomGenerationStatus.FINISHED)
                .build();

        Sbom sbom = createSBOM();
        sbom.setId("13");
        sbom.setIdentifier(BUILD_ID_2_DELETE);
        sbom.setGenerationRequest(generationRequest);
        sbomRepository.saveSbom(sbom);

        String rsqlQuery = "generationRequest.id=eq=" + REQUEST_ID_2_DELETE;
        List<Sbom> sbomsAfterInsert = sbomRepository
                .search(QueryParameters.builder().pageSize(10).rsqlQuery(rsqlQuery).build());
        assertEquals(1, sbomsAfterInsert.size());

        long beforeDeletion = SbomGenerationRequest.count("id = :id", Parameters.with("id", REQUEST_ID_2_DELETE));
        assertEquals(1, beforeDeletion);

        sbomGenerationRequestRepository.deleteRequest(REQUEST_ID_2_DELETE);

        List<Sbom> sbomsAfterDelete = sbomRepository
                .search(QueryParameters.builder().pageSize(10).rsqlQuery(rsqlQuery).build());
        assertEquals(0, sbomsAfterDelete.size());

        long afterDeletion = SbomGenerationRequest.count("id = :id", Parameters.with("id", REQUEST_ID_2_DELETE));
        assertEquals(0, afterDeletion);

    }

    @Test
    void testFindPendingOperationRequest() {
        long beforeInsertionSize = sbomGenerationRequestRepository.count();
        String id = "589A58D72C4D452";
        String identifier = "BAHVPNKYCYIAA";
        SbomGenerationRequest request = SbomGenerationRequest.builder()
                .withId(id)
                .withIdentifier(identifier)
                .withCreationTime(Instant.now())
                .withType(GenerationRequestType.OPERATION)
                .withStatus(SbomGenerationStatus.NO_OP)
                .build();
        sbomGenerationRequestRepository.persist(request);
        long afterInsertionSize = sbomGenerationRequestRepository.count();

        assertEquals(beforeInsertionSize + 1, afterInsertionSize);

        List<SbomGenerationRequest> pendingRequests = SbomGenerationRequest.findPendingRequests(identifier);
        assertEquals(1, pendingRequests.size());

        GenerationRequest req = new GenerationRequestBuilder(pendingRequests.get(0).getType())
                .withIdentifier(pendingRequests.get(0).getIdentifier())
                .withStatus(SbomGenerationStatus.NEW)
                .withId(pendingRequests.get(0).getId())
                .build();

        assertEquals(id, req.getId());
        assertEquals(identifier, req.getIdentifier());

    }
}
