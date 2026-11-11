package org.jboss.sbomer.cli.test.unit.feature.sbom.adjust;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.Set;
import java.util.stream.Collectors;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.BomReference;
import org.jboss.sbomer.cli.feature.sbom.adjuster.PncBuildAdjuster;
import org.jboss.sbomer.core.features.sbom.Constants;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.core.test.TestResources;
import org.junit.jupiter.api.Test;

class PncBuildAdjusterTest {
    @Test
    void shouldAddSerialNumber() throws IOException {
        PncBuildAdjuster adjuster = new PncBuildAdjuster();
        Bom bom = SbomUtils.fromString(TestResources.asString("boms/image.json"));
        assertNotNull(bom);
        bom.setSerialNumber(null);

        Bom adjusted = adjuster.adjust(bom);

        assertNotNull(adjusted.getSerialNumber());
        assertNotNull(adjusted.getMetadata().getSupplier());
        assertEquals(Constants.SUPPLIER_NAME, adjusted.getMetadata().getSupplier().getName());
        assertTrue(adjusted.getSerialNumber().startsWith("urn:uuid:"));
        assertEquals(45, adjusted.getSerialNumber().length());
    }

    @Test
    void parseBrewRpmsBom() throws IOException {
        Bom rpmBom = SbomUtils.fromPath(Paths.get("src", "test", "resources", "boms/brew_rpm.json"));
        assertNotNull(rpmBom);
        assertEquals(1, rpmBom.getDependencies().size());
        assertEquals(8, rpmBom.getDependencies().get(0).getProvides().size());

        Set<String> providedRefs = rpmBom.getDependencies()
                .stream()
                .flatMap(dependency -> dependency.getProvides().stream())
                .map(BomReference::getRef)
                .collect(Collectors.toSet());

        // Convert expectedRefs to a Set for comparison
        Set<String> expectedRefsSet = Set.of(
                "pkg:rpm/redhat/redhat-release-computenode@7.2-8.el7_2.1?arch=ppc",
                "pkg:rpm/redhat/redhat-release-computenode@7.2-8.el7_2.1?arch=s390",
                "pkg:rpm/redhat/redhat-release-computenode@7.2-8.el7_2.1?arch=ppc64le",
                "pkg:rpm/redhat/redhat-release-computenode@7.2-8.el7_2.1?arch=aarch64",
                "pkg:rpm/redhat/redhat-release-computenode@7.2-8.el7_2.1?arch=ppc64",
                "pkg:rpm/redhat/redhat-release-computenode@7.2-8.el7_2.1?arch=i686",
                "pkg:rpm/redhat/redhat-release-computenode@7.2-8.el7_2.1?arch=s390x",
                "pkg:rpm/redhat/redhat-release-computenode@7.2-8.el7_2.1?arch=x86_64");

        // Compare Sets
        assertEquals(providedRefs, expectedRefsSet);

        SbomUtils.validate(SbomUtils.toJsonNode(rpmBom));
    }
}
