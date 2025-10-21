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
package org.jboss.sbomer.cli.test.integ;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Optional;

import org.cyclonedx.model.Ancestors;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Pedigree;
import org.eclipse.microprofile.rest.client.RestClientBuilder;
import org.jboss.pnc.build.finder.core.BuildConfig;
import org.jboss.pnc.build.finder.core.ConfigDefaults;
import org.jboss.pnc.build.finder.koji.KojiClientSession;
import org.jboss.sbomer.cli.feature.sbom.client.CachitoClient;
import org.jboss.sbomer.cli.feature.sbom.client.CachitoResponse;
import org.jboss.sbomer.cli.feature.sbom.processor.DefaultProcessor;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.redhat.red.build.koji.KojiClientException;
import com.redhat.red.build.koji.model.xmlrpc.KojiBuildInfo;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;

@Disabled
@Slf4j
@QuarkusTest
class CachitoClientIT {
    @Test
    @DisplayName("Should successfully run Cachito client")
    void testCachitoClient() throws KojiClientException, IOException {
        BuildConfig buildConfig = BuildConfig.load(ConfigDefaults.CONFIG);

        try (KojiClientSession kojiClientSession = new KojiClientSession(buildConfig.getKojiHubURL())) {
            KojiBuildInfo buildInfo = kojiClientSession
                    .getBuildInfo("rhacs-main-container-4.4.8-2", kojiClientSession.getSession());
            log.info("build id: {}, extra: {}", buildInfo.getId(), buildInfo.getExtra());
            Optional<URI> optionalUri = DefaultProcessor.getUriFromBuildInfo(buildInfo);
            assertTrue(optionalUri.isPresent());
            URI uri = optionalUri.get();
            CachitoClient cachitoClient = RestClientBuilder.newBuilder().baseUri(uri).build(CachitoClient.class);
            log.info("uriInfo: {}", CachitoClient.uriInfo);
            List<String> cachitoRequestIdsFromBuildInfo = DefaultProcessor.getCachitoRequestIdsFromBuildInfo(buildInfo);
            log.info("cachitoRequestIdsFromBuildInfo: {}", cachitoRequestIdsFromBuildInfo);

            for (String id : cachitoRequestIdsFromBuildInfo) {
                log.info("cachitoRequestId: {}", id);
                Response response = cachitoClient.getRequestById(id);
                assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
                CachitoResponse cachitoResponse = response.readEntity(CachitoResponse.class);
                log.info("Request: {}", cachitoResponse);
                Component component = new Component();
                DefaultProcessor.addPedigreeFromBuildInfo(cachitoClient, component, buildInfo);
                Pedigree pedigree = component.getPedigree();
                assertNotNull(pedigree);
                Ancestors ancestors = pedigree.getAncestors();
                assertNotNull(ancestors);
                List<Component> components = ancestors.getComponents();
                assertEquals(2, components.size());
                Component component1 = components.get(0);
                assertEquals("49cc2ba8faecefb5654462814c00501076837483", component1.getVersion());
                assertEquals("https://github.com/stackrox/stackrox.git", component1.getPurl());
                Component component2 = components.get(1);
                assertEquals("0915c99f01b46f50af8e02da8b6528156f584b7c", component2.getVersion());
                assertEquals("https://github.com/facebook/rocksdb.git", component2.getPurl());
            }
        }
    }
}
