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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collection;

import org.jboss.sbomer.core.dto.BaseSbomRecord;
import org.jboss.sbomer.core.features.sbom.enums.GenerationRequestType;
import org.jboss.sbomer.core.features.sbom.rest.Page;
import org.jboss.sbomer.service.feature.sbom.model.Sbom;
import org.jboss.sbomer.service.feature.sbom.model.SbomGenerationRequest;
import org.jboss.sbomer.service.feature.sbom.service.SbomService;
import org.jboss.sbomer.service.test.utils.umb.TestUmbProfile;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;

@QuarkusTest
@TestProfile(TestUmbProfile.class)
@Slf4j
class SBOMServiceTest {

    @Inject
    SbomService sbomService;

    private static final String INITIAL_BUILD_ID = "ARYT3LBXDVYAC";

    private static final String GRAPHQL_PURL = "pkg:maven/org.eclipse.microprofile.graphql/microprofile-graphql-parent@1.1.0.redhat-00008?type=pom";

    private static final String GRAPHQL_SBOM_ID = "416640206274228224";

    private static final String GRAPHQL_REQUEST_ID = "AASSBB";

    @Test
    void testGetBaseSbom() {
        log.info("testGetBaseSbom ...");
        String rsqlQuery = "identifier=eq=" + INITIAL_BUILD_ID;
        Collection<BaseSbomRecord> sboms = sbomService.searchSbomRecordsByQueryPaginated(0, 1, rsqlQuery, null)
                .getContent();
        assertFalse(sboms.isEmpty());
    }

    @Test
    void testListBaseSboms() {
        log.info("testListBaseSboms ...");

        Sbom dummySbom = new Sbom();
        dummySbom.setIdentifier(INITIAL_BUILD_ID);

        sbomService.save(dummySbom);

        Page<BaseSbomRecord> page = sbomService.searchSbomRecordsByQueryPaginated(0, 50, null, null);
        assertEquals(0, page.getPageIndex());
        assertEquals(50, page.getPageSize());
        assertTrue(page.getTotalHits() > 0);
        assertEquals(1, page.getTotalPages());
        assertFalse(page.getContent().isEmpty());

        BaseSbomRecord foundSbom = null;
        for (BaseSbomRecord sbom : page.getContent()) {
            if (sbom.identifier().equals(INITIAL_BUILD_ID)) {
                foundSbom = sbom;
                break;
            }
        }

        assertNotNull(foundSbom);
    }

    @Nested
    class GetByPurl {
        @Test
        void testGetSbomByPurlNotFound() {
            Sbom sbom = sbomService.findByPurl("doesntexist");
            assertNull(sbom);
        }

        @Test
        void testGetSbomByPurl() {
            Sbom sbom = sbomService.findByPurl(GRAPHQL_PURL);

            assertNotNull(sbom);
            assertEquals(GRAPHQL_SBOM_ID, sbom.getId());
            assertEquals(GRAPHQL_PURL, sbom.getRootPurl());
        }

        @Test
        void testGetSbomByPurlHandlesEscapesAndQuotes() {
            assertNotNull(sbomService.findByPurl(GRAPHQL_PURL));
            assertNull(sbomService.findByPurl(GRAPHQL_PURL + "' or rootPurl!='"));
            assertNull(sbomService.findByPurl("' or rootPurl=='*"));
            assertNull(sbomService.findByPurl("' or id=='" + GRAPHQL_SBOM_ID));
            assertNull(sbomService.findByPurl("'"));
            assertNull(sbomService.findByPurl("\\"));
            assertNull(sbomService.findByPurl("a\\b'c"));
        }

        @Test
        void testGetSbomByPurlMrrcFallback() {
            String qualifier = "repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F";
            String newPurl = GRAPHQL_PURL + "&" + qualifier;
            Sbom sbom = sbomService.findByPurl(newPurl);
            assertNotNull(sbom);
            assertEquals(GRAPHQL_SBOM_ID, sbom.getId());
            assertEquals(GRAPHQL_PURL, sbom.getRootPurl());
        }

        @Test
        void testGetSbomByPurlNoFallback() {
            String qualifier = "repository_url=http://repo.maven.apache.org/maven2";
            String newPurl = GRAPHQL_PURL + "&" + qualifier;
            Sbom sbom = sbomService.findByPurl(newPurl);
            assertNull(sbom);
        }
    }

    @Test
    void testFindRequestByIdentifier() {
        SbomGenerationRequest request = sbomService
                .findRequestByIdentifier(GenerationRequestType.BUILD, INITIAL_BUILD_ID);
        assertNotNull(request);
        assertEquals(GRAPHQL_REQUEST_ID, request.getId());
        assertEquals(INITIAL_BUILD_ID, request.getIdentifier());
        assertEquals(GenerationRequestType.BUILD, request.getType());
    }

    @Test
    void testFindRequestByIdentifierHandlesEscapesAndQuotes() {
        assertNotNull(sbomService.findRequestByIdentifier(GenerationRequestType.BUILD, INITIAL_BUILD_ID));
        assertNull(
                sbomService
                        .findRequestByIdentifier(GenerationRequestType.BUILD, INITIAL_BUILD_ID + "' or identifier!='"));
        assertNull(sbomService.findRequestByIdentifier(GenerationRequestType.BUILD, "' or identifier=='*"));
        assertNull(sbomService.findRequestByIdentifier(GenerationRequestType.BUILD, "' or id=='" + GRAPHQL_REQUEST_ID));
        assertNull(sbomService.findRequestByIdentifier(GenerationRequestType.BUILD, "'"));
        assertNull(sbomService.findRequestByIdentifier(GenerationRequestType.BUILD, "\\"));
        assertNull(sbomService.findRequestByIdentifier(GenerationRequestType.BUILD, "a\\b'c"));
    }

    @Test
    void testFindByGenerationRequest() {
        Sbom sbom = sbomService.findByGenerationRequest(GRAPHQL_REQUEST_ID);
        assertNotNull(sbom);
        assertEquals(GRAPHQL_SBOM_ID, sbom.getId());
        assertEquals(GRAPHQL_REQUEST_ID, sbom.getGenerationRequest().getId());
    }

    @Test
    void testFindByGenerationRequestNotFound() {
        assertNull(sbomService.findByGenerationRequest("doesntexist"));
    }
}
