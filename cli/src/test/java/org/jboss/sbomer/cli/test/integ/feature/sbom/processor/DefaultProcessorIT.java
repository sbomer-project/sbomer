package org.jboss.sbomer.cli.test.integ.feature.sbom.processor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.ExternalReference.Type;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Hash.Algorithm;
import org.cyclonedx.model.Metadata;
import org.jboss.sbomer.cli.feature.sbom.client.CachitoClient;
import org.jboss.sbomer.cli.feature.sbom.processor.DefaultProcessor;
import org.jboss.sbomer.cli.feature.sbom.service.KojiService;
import org.jboss.sbomer.cli.test.utils.PncWireMock;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.core.pnc.PncService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import io.quarkus.test.common.WithTestResource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;

@QuarkusTest
@WithTestResource(PncWireMock.class)
class DefaultProcessorIT {

    DefaultProcessor defaultProcessor;

    @Inject
    PncService pncService;

    @BeforeEach
    void init() {
        this.defaultProcessor = new DefaultProcessor(
                pncService,
                Mockito.mock(KojiService.class),
                Mockito.mock(CachitoClient.class));
    }

    @Test
    void testProcessing() {
        // Prepare BOM!
        Bom bom = new Bom();

        Component component = new Component();
        component.setPurl("pkg:maven/org.ow2.asm/asm@9.1.0.redhat-00002?type=jar");
        component.setVersion("9.1.0.redhat-00002");
        component.setHashes(List.of(new Hash(Algorithm.SHA1, "2cdf6b457191ed82ef3a9d2e579f6d0aa495a533")));
        component.setType(Component.Type.LIBRARY);

        Metadata metadata = new Metadata();
        metadata.setComponent(component);

        bom.setMetadata(metadata);

        // Process!
        defaultProcessor.process(bom);

        assertEquals("Red Hat", component.getSupplier().getName());
        assertEquals("Red Hat", component.getPublisher());
        assertEquals("Red Hat", component.getPublisher());

        assertThat(
                SbomUtils.getExternalReferences(component, Type.BUILD_SYSTEM, "pnc-build-id").get(0).getUrl(),
                matchesPattern("^https://localhost:\\d+/pnc-rest/v2/builds/APT4PH2ILMAAA$"));
    }
}
