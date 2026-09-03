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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.jboss.sbomer.core.features.sbom.config.OperationConfig;
import org.jboss.sbomer.core.features.sbom.config.PncBuildConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.DefaultProcessorConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.GeneratorConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.ProcessorConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.RedHatProductProcessorConfig;
import org.jboss.sbomer.core.features.sbom.enums.GenerationRequestType;
import org.jboss.sbomer.core.features.sbom.enums.GeneratorType;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.service.feature.sbom.model.Sbom;
import org.jboss.sbomer.service.feature.sbom.service.SbomRepository;
import org.jboss.sbomer.service.rest.QueryParameters;
import org.jboss.sbomer.service.test.utils.QuarkusTransactionalTest;
import org.jboss.sbomer.service.test.utils.umb.TestUmbProfile;
import org.junit.jupiter.api.Test;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

import io.quarkus.logging.Log;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;

@QuarkusTransactionalTest
@TestProfile(TestUmbProfile.class)
class SbomRepositoryTest {

    @Inject
    Validator validator;

    @Inject
    SbomRepository sbomRepository;

    @Test
    void testNonNullRootComponents() {
        String rsqlQuery = "identifier=eq=ARYT3LBXDVYAC";
        Sbom sbom = sbomRepository.search(QueryParameters.builder().pageSize(1).rsqlQuery(rsqlQuery).build()).get(0);

        assertNotNull(sbom.getRootPurl());
        assertEquals(
                "pkg:maven/org.eclipse.microprofile.graphql/microprofile-graphql-parent@1.1.0.redhat-00008?type=pom",
                sbom.getRootPurl());
    }

    @Test
    void testValidBom() {
        String rsqlQuery = "identifier=eq=ARYT3LBXDVYAC";
        Sbom sbom = sbomRepository.search(QueryParameters.builder().pageSize(1).rsqlQuery(rsqlQuery).build()).get(0);
        Bom bom = SbomUtils.fromJsonNode(sbom.getSbom());

        assertEquals("CycloneDX", bom.getBomFormat());
        Component firstComponent = bom.getComponents().get(0);
        assertEquals("microprofile-graphql-spec", firstComponent.getName());
        assertEquals(
                "pkg:maven/org.eclipse.microprofile.graphql/microprofile-graphql-spec@1.1.0.redhat-00008?type=pom",
                firstComponent.getPurl());
        assertEquals("416640206274228224", sbom.getId());
        assertEquals("ARYT3LBXDVYAC", sbom.getIdentifier());

        Set<ConstraintViolation<Sbom>> violations = validator.validate(sbom);
        if (!violations.isEmpty()) {
            Log.error(
                    "violations: " + violations.stream()
                            .map(ConstraintViolation::getMessage)
                            .collect(Collectors.joining("\n\t")));
            fail("Validation errors on the baseSBOM entity should be empty!");
        }
    }

    @Test
    void testValidConfiguration() {
        String rsqlQuery = "identifier=eq=ARYT3LBXDVYAC";
        Sbom sbom = sbomRepository.search(QueryParameters.builder().pageSize(10).rsqlQuery(rsqlQuery).build()).get(0);

        assertEquals("416640206274228224", sbom.getId());
        assertEquals("ARYT3LBXDVYAC", ((PncBuildConfig) sbom.getGenerationRequest().getConfig()).getBuildId());

        GeneratorConfig generatorConfig = ((PncBuildConfig) sbom.getGenerationRequest().getConfig()).getProducts()
                .iterator()
                .next()
                .getGenerator();
        List<ProcessorConfig> processorConfigs = ((PncBuildConfig) sbom.getGenerationRequest().getConfig())
                .getProducts()
                .iterator()
                .next()
                .getProcessors();
        assertEquals(GeneratorType.MAVEN_DOMINO, generatorConfig.getType());
        assertEquals(
                "--config-file .domino/manifest/quarkus-bom-config.json --warn-on-missing-scm",
                generatorConfig.getArgs());
        assertEquals("0.0.90", generatorConfig.getVersion());

        assertEquals(2, processorConfigs.size());

        DefaultProcessorConfig defaultProcessorConfig = (DefaultProcessorConfig) processorConfigs.get(0);
        assertEquals(List.of("default"), defaultProcessorConfig.toCommand());

        RedHatProductProcessorConfig redHatProductProcessorConfig = (RedHatProductProcessorConfig) processorConfigs
                .get(1);
        assertEquals("RHBQ", redHatProductProcessorConfig.getErrata().getProductName());
        assertEquals("RHEL-8-RHBQ-2.13", redHatProductProcessorConfig.getErrata().getProductVersion());
        assertEquals("8Base-RHBQ-2.13", redHatProductProcessorConfig.getErrata().getProductVariant());
    }

    @Test
    void testFindByIdSbom() {
        Sbom sbom = sbomRepository.findById("416640206274228224");

        assertEquals("416640206274228224", sbom.getId());
        assertEquals("ARYT3LBXDVYAC", sbom.getIdentifier());
        assertEquals(GenerationRequestType.BUILD, sbom.getGenerationRequest().getType());
    }

    @Test
    void testFindByGenerationIdEmpty() {
        List<Sbom> sboms = sbomRepository.findSbomsByGenerationRequest("NOTTHERE");
        assertTrue(sboms.isEmpty());
    }

    @Test
    void testFindByGenerationIdSingle() {
        List<Sbom> sboms = sbomRepository.findSbomsByGenerationRequest("AASSBB");
        assertEquals(1, sboms.size());
    }

    @Test
    void testNonNullRootOperationComponents() {
        String rsqlQuery = "identifier=eq=OPBGCD23DVYAC";
        Sbom sbom = sbomRepository.search(QueryParameters.builder().pageSize(1).rsqlQuery(rsqlQuery).build()).get(0);

        assertNotNull(sbom.getRootPurl());
        assertEquals("pkg:generic/my-broker-7.11.5.CR3-bin.zip@7.11.5.CR3?operation=OPBGCD23DVYAC", sbom.getRootPurl());
    }

    @Test
    void testRSQLLike() {
        String rsqlQuery = "rootPurl=like='%my broker 7.11.5%'";
        List<Sbom> sboms = sbomRepository
                .search(QueryParameters.builder().pageIndex(0).pageSize(10).rsqlQuery(rsqlQuery).build());
        assertEquals(1, sboms.size());
        assertEquals("816640206274228223", sboms.get(0).getId());
    }

    @Test
    void testValidOperationBom() {
        String rsqlQuery = "identifier=eq=OPBGCD23DVYAC";
        Sbom sbom = sbomRepository.search(QueryParameters.builder().pageSize(1).rsqlQuery(rsqlQuery).build()).get(0);
        Bom bom = SbomUtils.fromJsonNode(sbom.getSbom());

        assertEquals("CycloneDX", bom.getBomFormat());
        Component firstComponent = bom.getComponents().get(0);
        assertEquals("error_prone_annotations", firstComponent.getName());
        assertEquals(
                "pkg:maven/com.google.errorprone/error_prone_annotations@2.2.0?type=jar",
                firstComponent.getPurl());
        assertEquals("816640206274228223", sbom.getId());
        assertEquals("OPBGCD23DVYAC", sbom.getIdentifier());
        assertEquals(GenerationRequestType.OPERATION, sbom.getGenerationRequest().getType());

        Set<ConstraintViolation<Sbom>> violations = validator.validate(sbom);
        if (!violations.isEmpty()) {
            Log.error(
                    "violations: " + violations.stream()
                            .map(ConstraintViolation::getMessage)
                            .collect(Collectors.joining("\n\t")));
            fail("Validation errors on the baseSBOM entity should be empty!");
        }
    }

    @Test
    void testValidOperationConfiguration() {
        String rsqlQuery = "identifier=eq=OPBGCD23DVYAC";
        Sbom sbom = sbomRepository.search(QueryParameters.builder().pageSize(10).rsqlQuery(rsqlQuery).build()).get(0);

        assertEquals("816640206274228223", sbom.getId());
        assertEquals("OPBGCD23DVYAC", ((OperationConfig) sbom.getGenerationRequest().getConfig()).getOperationId());

        GeneratorConfig generatorConfig = ((OperationConfig) sbom.getGenerationRequest().getConfig()).getProduct()
                .getGenerator();
        List<ProcessorConfig> processorConfigs = ((OperationConfig) sbom.getGenerationRequest().getConfig())
                .getProduct()
                .getProcessors();
        assertEquals(GeneratorType.CYCLONEDX_OPERATION, generatorConfig.getType());
        assertNull(generatorConfig.getArgs());
        assertNull(generatorConfig.getVersion());

        assertEquals(1, processorConfigs.size());

        RedHatProductProcessorConfig redHatProductProcessorConfig = (RedHatProductProcessorConfig) processorConfigs
                .get(0);
        assertEquals(
                List.of(
                        "redhat-product",
                        "--productName",
                        "RHBQ",
                        "--productVersion",
                        "RHEL-8-RHBQ-2.13",
                        "--productVariant",
                        "8Base-RHBQ-2.13"),
                redHatProductProcessorConfig.toCommand());
        assertEquals("RHBQ", redHatProductProcessorConfig.getErrata().getProductName());
        assertEquals("RHEL-8-RHBQ-2.13", redHatProductProcessorConfig.getErrata().getProductVersion());
        assertEquals("8Base-RHBQ-2.13", redHatProductProcessorConfig.getErrata().getProductVariant());
    }

    @Test
    void testFindByIdOperationSbom() {
        Sbom sbom = sbomRepository.findById("816640206274228223");

        assertEquals("816640206274228223", sbom.getId());
        assertEquals("OPBGCD23DVYAC", sbom.getIdentifier());
        assertEquals(GenerationRequestType.OPERATION, sbom.getGenerationRequest().getType());
    }

    @Test
    void testRootPurlIsCanonicalized() throws MalformedPackageURLException {
        Bom bom = SbomUtils.createBom();
        assertNotNull(bom);
        String purl = "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.14.1.redhat-00001?type=jar&classifier=sources";
        Component mainComponent = SbomUtils.createComponent(
                "com.fasterxml.jackson.core",
                "jackson-core",
                "2.14.1.redhat-00001",
                null,
                purl,
                Component.Type.LIBRARY);
        assertEquals(purl, mainComponent.getPurl());
        bom.setMetadata(SbomUtils.createDefaultSbomerMetadata(mainComponent, "2.14.1.redhat-00001"));
        Sbom sbom = Sbom.builder().withSbom(SbomUtils.toJsonNode(bom)).build();
        sbom.prePersist();
        assertEquals(new PackageURL(purl).toString(), sbom.getRootPurl());
    }
}
