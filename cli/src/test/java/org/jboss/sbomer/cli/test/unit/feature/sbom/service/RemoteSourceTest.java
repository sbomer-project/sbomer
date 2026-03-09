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
package org.jboss.sbomer.cli.test.unit.feature.sbom.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.jboss.pnc.build.finder.koji.ClientSession;
import org.jboss.sbomer.cli.feature.sbom.client.KojiDownloadClient;
import org.jboss.sbomer.cli.feature.sbom.client.RemoteSource;
import org.jboss.sbomer.cli.feature.sbom.service.KojiService;
import org.jboss.sbomer.cli.test.utils.KojiBuildInfoFactory;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.redhat.red.build.koji.model.xmlrpc.KojiBuildInfo;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

class RemoteSourceTest {
    private static final int BUILD_ID = 123;

    private static final int PACKAGE_ID = 456;

    private static final String N = "foo-container";

    private static final String V = "1.0.0";

    private static final String R = "1.el9";

    private final KojiDownloadClient downloadClient = mock(KojiDownloadClient.class);

    private KojiService kojiService;

    private static KojiBuildInfo newBuildInfo(String... names) {
        return KojiBuildInfoFactory.withRemoteSources(new KojiBuildInfo(BUILD_ID, PACKAGE_ID, N, V, R), names);
    }

    private static Response jsonResponse(String json) {
        return Response
                .ok(new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)), MediaType.APPLICATION_OCTET_STREAM)
                .build();
    }

    @BeforeEach
    void init() {
        kojiService = new KojiService();
        kojiService.setKojiSession(mock(ClientSession.class));
        kojiService.setKojiDownloadClient(downloadClient);
    }

    @Test
    void testDefaultSource() {
        KojiBuildInfo buildInfo = newBuildInfo((String) null);
        when(downloadClient.downloadSourcesFile(N, V, R, "remote-source.json"))
                .thenReturn(jsonResponse("{\"repo\":\"https://foo\",\"ref\":\"bar\"}"));
        List<RemoteSource> result = kojiService.downloadRemoteSources(buildInfo);
        assertEquals(1, result.size());
        RemoteSource remoteSource = result.get(0);
        assertEquals("https://foo", remoteSource.getRepo());
        assertEquals("bar", remoteSource.getRef());
    }

    @Test
    void testNamedSources() {
        KojiBuildInfo buildInfo = newBuildInfo("bar", "baz");
        when(downloadClient.downloadSourcesFile(N, V, R, "remote-source-bar.json"))
                .thenReturn(jsonResponse("{\"repo\":\"https://bar\",\"ref\":\"foo\"}"));
        when(downloadClient.downloadSourcesFile(N, V, R, "remote-source-baz.json"))
                .thenReturn(jsonResponse("{\"repo\":\"https://baz\",\"ref\":\"foo\"}"));
        List<RemoteSource> result = kojiService.downloadRemoteSources(buildInfo);
        assertEquals(2, result.size());
        RemoteSource remoteSource1 = result.get(0);
        assertEquals("https://bar", remoteSource1.getRepo());
        assertEquals("foo", remoteSource1.getRef());
        RemoteSource remoteSource2 = result.get(1);
        assertEquals("https://baz", remoteSource2.getRepo());
        assertEquals("foo", remoteSource2.getRef());
    }

    @Test
    void testFailure() {
        KojiBuildInfo buildInfo = newBuildInfo("bar", "baz");
        when(downloadClient.downloadSourcesFile(N, V, R, "remote-source-bar.json"))
                .thenReturn(jsonResponse("{\"repo\":\"https://bar\",\"ref\":\"a\"}"));
        when(downloadClient.downloadSourcesFile(N, V, R, "remote-source-baz.json"))
                .thenReturn(Response.status(Response.Status.NOT_FOUND).build());
        assertThrows(ApplicationException.class, () -> kojiService.downloadRemoteSources(buildInfo));
    }
}
