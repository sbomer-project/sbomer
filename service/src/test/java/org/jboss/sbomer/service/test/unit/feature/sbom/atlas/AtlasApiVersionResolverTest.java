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
package org.jboss.sbomer.service.test.unit.feature.sbom.atlas;

import static org.jboss.sbomer.service.feature.sbom.atlas.AtlasApiVersionResolver.V2;
import static org.jboss.sbomer.service.feature.sbom.atlas.AtlasApiVersionResolver.V3;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.jboss.sbomer.service.feature.FeatureFlags;
import org.jboss.sbomer.service.feature.sbom.atlas.AtlasApiVersionResolver;
import org.jboss.sbomer.service.feature.sbom.atlas.AtlasBuildInfoClient;
import org.jboss.sbomer.service.feature.sbom.atlas.AtlasInfo;
import org.jboss.sbomer.service.feature.sbom.atlas.AtlasReleaseInfoClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AtlasApiVersionResolverTest {

    AtlasApiVersionResolver resolver;

    final AtlasBuildInfoClient buildInfoClient = mock(AtlasBuildInfoClient.class);
    final AtlasReleaseInfoClient releaseInfoClient = mock(AtlasReleaseInfoClient.class);
    final FeatureFlags featureFlags = mock(FeatureFlags.class);

    private static AtlasInfo info(String version) {
        AtlasInfo info = new AtlasInfo();
        info.setVersion(version);
        return info;
    }

    @BeforeEach
    void beforeEach() {
        resolver = new AtlasApiVersionResolver();
        resolver.setAtlasBuildInfoClient(buildInfoClient);
        resolver.setAtlasReleaseInfoClient(releaseInfoClient);
        resolver.setFeatureFlags(featureFlags);

        when(featureFlags.atlasForceV3()).thenReturn(false);
    }

    @Test
    void olderServerResolvesToV2() {
        when(buildInfoClient.info()).thenReturn(info("0.4.2"));
        assertEquals(V2, resolver.resolve(false));
    }

    @Test
    void thresholdServerResolvesToV3() {
        when(buildInfoClient.info()).thenReturn(info("0.5.0"));
        assertEquals(V3, resolver.resolve(false));
    }

    @Test
    void newerServerResolvesToV3() {
        when(releaseInfoClient.info()).thenReturn(info("0.6.0-rc.1"));
        assertEquals(V3, resolver.resolve(true));
    }

    @Test
    void detectionFailureFallsBackToV2() {
        when(buildInfoClient.info()).thenThrow(new RuntimeException("connection refused"));
        assertEquals(V2, resolver.resolve(false));
    }

    @Test
    void unparseableVersionFallsBackToV2() {
        when(buildInfoClient.info()).thenReturn(info("not-a-version"));
        assertEquals(V2, resolver.resolve(false));
    }

    @Test
    void forceV3FlagBypassesDetection() {
        when(featureFlags.atlasForceV3()).thenReturn(true);

        assertEquals(V3, resolver.resolve(false));
        verify(buildInfoClient, never()).info();
    }

    @Test
    void versionIsProbedOnEachResolve() {
        when(buildInfoClient.info()).thenReturn(info("0.6.0"));

        assertEquals(V3, resolver.resolve(false));
        assertEquals(V3, resolver.resolve(false));

        // The version is not cached; each publish batch re-probes the server so a fallback is never pinned.
        verify(buildInfoClient, times(2)).info();
    }

    @Test
    void buildAndReleaseAreResolvedIndependently() {
        when(buildInfoClient.info()).thenReturn(info("0.4.0"));
        when(releaseInfoClient.info()).thenReturn(info("0.6.0"));

        assertEquals(V2, resolver.resolve(false));
        assertEquals(V3, resolver.resolve(true));
    }

    @Test
    void supportsV3VersionMatrix() {
        assertFalse(AtlasApiVersionResolver.supportsV3(null));
        assertFalse(AtlasApiVersionResolver.supportsV3(""));
        assertFalse(AtlasApiVersionResolver.supportsV3("0.4.99"));
        assertTrue(AtlasApiVersionResolver.supportsV3("0.5.0"));
        assertTrue(AtlasApiVersionResolver.supportsV3("0.6.0-rc.1"));
        assertTrue(AtlasApiVersionResolver.supportsV3("1.0.0"));
        assertFalse(AtlasApiVersionResolver.supportsV3("garbage"));
    }
}
