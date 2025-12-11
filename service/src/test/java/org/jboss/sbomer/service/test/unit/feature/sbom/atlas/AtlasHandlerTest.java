package org.jboss.sbomer.service.test.unit.feature.sbom.atlas;

import static org.jboss.sbomer.service.feature.sbom.atlas.AtlasHandler.LABELS;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.cyclonedx.model.Bom;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.errors.ClientException;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.core.test.TestResources;
import org.jboss.sbomer.service.feature.FeatureFlags;
import org.jboss.sbomer.service.feature.sbom.atlas.AtlasBuildClient;
import org.jboss.sbomer.service.feature.sbom.atlas.AtlasClient;
import org.jboss.sbomer.service.feature.sbom.atlas.AtlasHandler;
import org.jboss.sbomer.service.feature.sbom.atlas.AtlasReleaseClient;
import org.jboss.sbomer.service.feature.sbom.model.Sbom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;

class AtlasHandlerTest {
    static class AtlasHandlerAlt extends AtlasHandler {
        @Override
        public void uploadManifest(Sbom sbom, AtlasClient atlasClient) throws ApplicationException {
            super.uploadManifest(sbom, atlasClient);
        }
    }

    AtlasHandlerAlt atlasHandler;

    final AtlasBuildClient atlasBuildClient = mock(AtlasBuildClient.class);
    final AtlasReleaseClient atlasReleaseClient = mock(AtlasReleaseClient.class);

    private Sbom generateSbom(String id, String purl) throws IOException {
        return generateSbom(id, purl, "sboms/complete_operation_sbom.json");
    }

    private Sbom generateSbom(String id, String purl, String path) throws IOException {
        Sbom sbom = new Sbom();
        sbom.setId(id);
        sbom.setRootPurl(purl);

        Bom bom = SbomUtils.fromString(TestResources.asString(path));
        bom.getMetadata().getComponent().setPurl(purl);
        sbom.setSbom(SbomUtils.toJsonNode(bom));

        return sbom;
    }

    @BeforeEach
    void beforeEach() {
        atlasHandler = new AtlasHandlerAlt();

        FeatureFlags featureFlags = mock(FeatureFlags.class);
        when(featureFlags.atlasReleasePublish()).thenReturn(true);
        when(featureFlags.atlasBuildPublish()).thenReturn(true);
        atlasHandler.setFeatureFlags(featureFlags);

        atlasHandler.setAtlasBuildClient(atlasBuildClient);
        atlasHandler.setAtlasReleaseClient(atlasReleaseClient);
    }

    @Test
    void testUploadNothing() {
        // Should not fail, just a warning should be added
        assertDoesNotThrow(() -> atlasHandler.publishBuildManifests(null));
        assertDoesNotThrow(() -> atlasHandler.publishReleaseManifests(null));
    }

    @Test
    void testUploadEmpty() {
        // Should not fail, just a warning should be added
        assertDoesNotThrow(() -> atlasHandler.publishBuildManifests(Collections.emptyList()));
        assertDoesNotThrow(() -> atlasHandler.publishReleaseManifests(Collections.emptyList()));
    }

    @Test
    void testUploadBoms() throws Exception {
        Sbom sbomA = generateSbom("AAA", "pkg:maven/compA@1.1.0?type=pom");
        Sbom sbomB = generateSbom("BBB", "pkg:maven/compB@1.1.0?type=pom");
        List<Sbom> sboms = List.of(sbomA, sbomB);

        atlasHandler.publishBuildManifests(sboms);
        atlasHandler.publishReleaseManifests(sboms);

        verify(atlasBuildClient, times(1)).upload(eq(LABELS), eq(sbomA.getSbom()));
        verify(atlasBuildClient, times(1)).upload(eq(LABELS), eq(sbomB.getSbom()));
        verify(atlasReleaseClient, times(1)).upload(eq(LABELS), eq(sbomA.getSbom()));
        verify(atlasReleaseClient, times(1)).upload(eq(LABELS), eq(sbomB.getSbom()));
    }

    @Test
    void testHandlingOfApiErrors() throws Exception {
        Sbom sbom = generateSbom("AAA", "pkg:maven/compA@1.1.0?type=pom");
        List<Sbom> sboms = List.of(sbom);
        String reason = "A reason";

        doThrow(new ClientException(reason)).when(atlasBuildClient).upload(any(Map.class), any(JsonNode.class));
        doThrow(new ClientException(reason)).when(atlasReleaseClient).upload(any(Map.class), any(JsonNode.class));

        ApplicationException ex1 = assertThrows(
                ApplicationException.class,
                () -> atlasHandler.publishBuildManifests(sboms));
        ApplicationException ex2 = assertThrows(
                ApplicationException.class,
                () -> atlasHandler.publishReleaseManifests(sboms));

        verify(atlasBuildClient, times(1)).upload(eq(LABELS), eq(sbom.getSbom()));
        verify(atlasReleaseClient, times(1)).upload(eq(LABELS), eq(sbom.getSbom()));

        String message = "Unable to store '" + sbom.getId() + "' manifest in Atlas, purl: '" + sbom.getRootPurl()
                + "': " + reason;
        assertEquals(message, ex1.getMessage());
        assertEquals(message, ex2.getMessage());
    }
}
