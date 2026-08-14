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
import static org.mockito.Mockito.spy;

import java.util.Collection;

import org.jboss.sbomer.core.dto.BaseSbomRecord;
import org.jboss.sbomer.core.features.sbom.rest.Page;
import org.jboss.sbomer.service.feature.sbom.model.Sbom;
import org.jboss.sbomer.service.feature.sbom.service.SbomRepository;
import org.jboss.sbomer.service.feature.sbom.service.SbomService;
import org.jboss.sbomer.service.rest.QueryParameters;
import org.jboss.sbomer.service.test.utils.umb.TestUmbProfile;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import io.quarkus.arc.ClientProxy;
import io.quarkus.test.junit.QuarkusMock;
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

    @Inject
    SbomRepository sbomRepository;

    private static final String INITIAL_BUILD_ID = "ARYT3LBXDVYAC";

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
            SbomRepository sbomRepositorySpy = spy(ClientProxy.unwrap(sbomRepository));
            QuarkusMock.installMockForInstance(sbomRepositorySpy, sbomRepository);

            // Part of the import.sql
            String purl = "pkg:maven/org.eclipse.microprofile.graphql/microprofile-graphql-parent@1.1.0.redhat-00008?type=pom";
            Sbom sbom = sbomService.findByPurl(purl);

            assertNotNull(sbom);

            Mockito.verify(sbomRepositorySpy, Mockito.times(1))
                    .search(
                            QueryParameters.builder()
                                    .rsqlQuery("rootPurl=eq='" + purl + "'")
                                    .sort("creationTime=desc=")
                                    .pageSize(10)
                                    .pageIndex(0)
                                    .build());

            assertEquals("416640206274228224", sbom.getId());
            assertEquals(purl, sbom.getRootPurl());
        }

        @Test
        void testGetSbomByPurlMrrcFallback() {
            String purl = "pkg:maven/org.eclipse.microprofile.graphql/microprofile-graphql-parent@1.1.0.redhat-00008?type=pom";
            String qualifier = "repository_url=https%3A%2F%2Fmaven.repository.redhat.com%2Fga%2F";
            String newPurl = purl + "&" + qualifier;
            Sbom sbom = sbomService.findByPurl(newPurl);
            assertNotNull(sbom);
            assertEquals("416640206274228224", sbom.getId());
            assertEquals(purl, sbom.getRootPurl());
        }

        @Test
        void testGetSbomByPurlNoFallback() {
            String purl = "pkg:maven/org.eclipse.microprofile.graphql/microprofile-graphql-parent@1.1.0.redhat-00008?type=pom";
            String qualifier = "repository_url=http://repo.maven.apache.org/maven2";
            String newPurl = purl + "&" + qualifier;
            Sbom sbom = sbomService.findByPurl(newPurl);
            assertNull(sbom);
        }
    }
}
