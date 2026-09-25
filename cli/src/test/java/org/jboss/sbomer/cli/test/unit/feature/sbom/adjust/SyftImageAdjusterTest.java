package org.jboss.sbomer.cli.test.unit.feature.sbom.adjust;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.component.evidence.Identity;
import org.jboss.sbomer.cli.feature.sbom.adjuster.SyftImageAdjuster;
import org.jboss.sbomer.core.features.sbom.Constants;
import org.jboss.sbomer.core.features.sbom.utils.PurlSanitizer;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.core.test.TestResources;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

class SyftImageAdjusterTest {

    @TempDir
    Path tmpDir;
    Bom bom = null;
    Path sourcesManifestPath = null;
    Path sourcesMetadataPath = null;

    static final String GO_IMAGE_SKOPEO = "go-image-skopeo.json";
    static final String GO_IMAGE = "go-image.json";
    static final String GO_IMAGE_SOURCES = "go-image-sources.json";
    static final String GO_IMAGE_SOURCES_METADATA = "go-image-sources-metadata.json";
    static final String BOMS = "boms/";
    static final String SKOPEO = "skopeo.json";

    SyftImageAdjuster createDefaultAdjuster() {
        return new SyftImageAdjuster(tmpDir, null, true, sourcesManifestPath, sourcesMetadataPath);
    }

    @BeforeEach
    void init() throws IOException {
        this.sourcesManifestPath = tmpDir.resolve(GO_IMAGE_SOURCES);
        this.sourcesMetadataPath = tmpDir.resolve(GO_IMAGE_SOURCES_METADATA);
        this.bom = SbomUtils.fromString(TestResources.asString(BOMS + GO_IMAGE));
        Files.writeString(tmpDir.resolve(SKOPEO), TestResources.asString(GO_IMAGE_SKOPEO));
        Files.writeString(this.sourcesManifestPath, TestResources.asString(BOMS + GO_IMAGE_SOURCES));
        Files.writeString(this.sourcesMetadataPath, TestResources.asString(GO_IMAGE_SOURCES_METADATA));
    }

    @Test
    void removeAllRpms() throws IOException {
        SyftImageAdjuster adjuster = new SyftImageAdjuster(
                tmpDir,
                null,
                false,
                sourcesManifestPath,
                sourcesMetadataPath);

        assertEquals(7, bom.getComponents().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        assertEquals(
                "pkg:oci/ose-cluster-cloud-controller-manager-operator@sha256%3A0897e7dcf7a971b493755010b7893b4a44800fe5032463676d016e3fe3b42d61?arch=amd64&os=linux&tag=v4.14.0-202411130434.p0.ga0b9c0d.assembly.stream.el8",
                adjusted.getMetadata().getComponent().getPurl());
        assertEquals(
                "openshift/ose-cluster-cloud-controller-manager-operator",
                adjusted.getMetadata().getComponent().getName());
        assertEquals(14, adjusted.getComponents().size());
        assertEquals(14, adjusted.getDependencies().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
    }

    @Test
    void removeAllRpmsLeaveImagePrefix() throws IOException {
        SyftImageAdjuster adjuster = new SyftImageAdjuster(
                tmpDir,
                List.of("/azure-config-credentials-injector"),
                false,
                sourcesManifestPath,
                sourcesMetadataPath);

        assertEquals(7, bom.getComponents().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        // The source-manifest components carry source-relative locations, so they are retained even though
        // the image 'paths' filter only allows an image prefix (SBOMER-583).
        assertEquals(9, adjusted.getComponents().size());
        assertEquals(9, adjusted.getDependencies().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
    }

    @Test
    void removeAllRpmsLeaveSourcesPrefix() throws IOException {
        SyftImageAdjuster adjuster = new SyftImageAdjuster(
                tmpDir,
                List.of("app"),
                false,
                sourcesManifestPath,
                sourcesMetadataPath);

        assertEquals(7, bom.getComponents().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        assertEquals(4, adjusted.getComponents().size());
        assertEquals(4, adjusted.getDependencies().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
    }

    @Test
    void removeAllRpmsLeavePrefixes() throws IOException {
        SyftImageAdjuster adjuster = new SyftImageAdjuster(
                tmpDir,
                List.of("/azure-config-credentials-injector", "app"),
                false,
                sourcesManifestPath,
                sourcesMetadataPath);

        assertEquals(7, bom.getComponents().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        assertEquals(9, adjusted.getComponents().size());
        assertEquals(9, adjusted.getDependencies().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
    }

    @Test
    void preserveRpms() throws IOException {
        SyftImageAdjuster adjuster = createDefaultAdjuster();

        assertEquals(7, bom.getComponents().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        assertEquals(16, adjusted.getComponents().size());
        assertEquals(16, adjusted.getDependencies().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
    }

    @Test
    void preserveRpmsWithImagePrefix() throws IOException {
        SyftImageAdjuster adjuster = new SyftImageAdjuster(
                tmpDir,
                List.of("/azure-config-credentials-injector"),
                true,
                sourcesManifestPath,
                sourcesMetadataPath);

        assertEquals(7, bom.getComponents().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        // The source-manifest components carry source-relative locations, so they are retained even though
        // the image 'paths' filter only allows an image prefix (SBOMER-583).
        assertEquals(11, adjusted.getComponents().size());
        assertEquals(11, adjusted.getDependencies().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
    }

    @Test
    void preserveRpmsWithSourcesPrefix() throws IOException {
        SyftImageAdjuster adjuster = new SyftImageAdjuster(
                tmpDir,
                List.of("app"),
                true,
                sourcesManifestPath,
                sourcesMetadataPath);

        assertEquals(7, bom.getComponents().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        assertEquals(6, adjusted.getComponents().size());
        assertEquals(6, adjusted.getDependencies().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
    }

    @Test
    void preserveRpmsWithPrefixes() throws IOException {
        SyftImageAdjuster adjuster = new SyftImageAdjuster(
                tmpDir,
                List.of("/azure-config-credentials-injector", "app"),
                true,
                sourcesManifestPath,
                sourcesMetadataPath);

        assertEquals(7, bom.getComponents().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        assertEquals(11, adjusted.getComponents().size());
        assertEquals(11, adjusted.getDependencies().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
    }

    @Test
    void noSourcesManifest() throws IOException {
        SyftImageAdjuster adjuster = new SyftImageAdjuster(tmpDir, null, false, null, sourcesMetadataPath);

        assertEquals(7, bom.getComponents().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        assertEquals(11, adjusted.getComponents().size());
        assertEquals(11, adjusted.getDependencies().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
    }

    @Test
    void noSourcesMetadata() throws IOException {
        SyftImageAdjuster adjuster = new SyftImageAdjuster(tmpDir, null, false, sourcesManifestPath, null);

        assertEquals(7, bom.getComponents().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        assertEquals(9, adjusted.getComponents().size());
        assertEquals(9, adjusted.getDependencies().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
    }

    @Test
    void noSources() throws IOException {
        SyftImageAdjuster adjuster = new SyftImageAdjuster(tmpDir, null, false, null, null);

        assertEquals(7, bom.getComponents().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        assertEquals(6, adjusted.getComponents().size());
        assertEquals(6, adjusted.getDependencies().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
    }

    // https://issues.redhat.com/browse/SBOMER-583
    @Test
    void shouldRetainSourceComponentsWhenImagePathScoped() throws IOException {
        // A sources manifest carrying an npm dependency with a source-relative location, as produced by
        // scanning the build's Cachito remote sources. This mirrors the reporter's dropped packages.
        String sourcesManifest = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "metadata": {
                    "component": { "bom-ref": "source-archive", "type": "file", "name": "remote-source.tar.gz" }
                  },
                  "components": [
                    {
                      "bom-ref": "pkg:npm/dompurify@3.4.11",
                      "type": "library",
                      "name": "dompurify",
                      "version": "3.4.11",
                      "purl": "pkg:npm/dompurify@3.4.11",
                      "properties": [
                        { "name": "syft:package:type", "value": "npm" },
                        { "name": "syft:location:0:path", "value": "app/ui/ui-docs/package-lock.json" }
                      ]
                    }
                  ]
                }
                """;
        Path npmSourcesPath = tmpDir.resolve("npm-sources.json");
        Files.writeString(npmSourcesPath, sourcesManifest);

        // Image scan scoped to /opt, as when the syft-manifest-opt feature flag is enabled. None of the
        // image components live under /opt, but the source component must not be filtered by this path.
        SyftImageAdjuster adjuster = new SyftImageAdjuster(tmpDir, List.of("/opt"), false, npmSourcesPath, null);

        Bom adjusted = adjuster.adjust(bom);

        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
        assertTrue(
                adjusted.getComponents().stream().anyMatch(c -> "pkg:npm/dompurify@3.4.11".equals(c.getPurl())),
                "The npm component merged from the sources manifest should survive the image '/opt' path filter");
    }

    @Test
    void hasSourcesManifestComponent() throws IOException {
        SyftImageAdjuster adjuster = createDefaultAdjuster();

        assertEquals(7, bom.getComponents().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        assertEquals(16, adjusted.getComponents().size());
        assertEquals(16, adjusted.getDependencies().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
        assertNotNull(
                adjusted.getComponents()
                        .stream()
                        .filter(c -> c.getBomRef().equals("pkg:golang/4d63.com/gocheckcompilerdirectives@v1.2.1"))
                        .findFirst()
                        .orElse(null));
    }

    @Test
    void hasSourcesMetadataComponent() throws IOException {
        SyftImageAdjuster adjuster = createDefaultAdjuster();

        assertEquals(7, bom.getComponents().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        assertEquals(16, adjusted.getComponents().size());
        assertEquals(16, adjusted.getDependencies().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
        assertNotNull(
                adjusted.getComponents()
                        .stream()
                        .filter(c -> c.getBomRef().equals("pkg:golang/bufio@go1.20.12"))
                        .findFirst()
                        .orElse(null));
    }

    @Test
    void shouldLeaveOnlyArchAndEpochQualifiers() throws IOException {
        SyftImageAdjuster adjuster = createDefaultAdjuster();

        assertEquals("pkg:golang/github.com/spf13/cobra@v1.8.0", bom.getComponents().get(2).getPurl());
        assertEquals(
                "pkg:rpm/redhat/subscription-manager-rhsm-certificates@20220623-1.el8?arch=noarch&distro=rhel-8.10&upstream=subscription-manager-rhsm-certificates-20220623-1.el8.src.rpm",
                bom.getComponents().get(6).getPurl());

        assertEquals(
                "pkg:golang/github.com/spf13/cobra@v1.8.0?package-id=62fa7d3ce006f31d",
                bom.getComponents().get(2).getBomRef());
        assertEquals(
                "pkg:rpm/redhat/subscription-manager-rhsm-certificates@20220623-1.el8?arch=noarch&distro=rhel-8.10&package-id=d9c9f52a5046ede8&upstream=subscription-manager-rhsm-certificates-20220623-1.el8.src.rpm",
                bom.getComponents().get(6).getBomRef());

        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        // 2nd component before adjustment becomes 7th after adding main component and sources
        assertEquals("pkg:golang/github.com/spf13/cobra@v1.8.0", adjusted.getComponents().get(6).getPurl());
        assertEquals(
                "pkg:rpm/redhat/subscription-manager-rhsm-certificates@20220623-1.el8?arch=noarch",
                adjusted.getComponents().get(1).getPurl());

        assertEquals("pkg:golang/github.com/spf13/cobra@v1.8.0", adjusted.getComponents().get(6).getBomRef());
        assertEquals(
                "pkg:rpm/redhat/subscription-manager-rhsm-certificates@20220623-1.el8?arch=noarch",
                adjusted.getComponents().get(1).getBomRef());

        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
    }

    @Test
    void shouldAdjustNameAndPurl() throws IOException {
        SyftImageAdjuster adjuster = createDefaultAdjuster();

        assertEquals(
                "registry-proxy.engineering.redhat.com/rh-osbs/openshift-ose-cluster-cloud-controller-manager-operator",
                bom.getMetadata().getComponent().getName());
        assertNull(bom.getMetadata().getComponent().getPurl());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        assertEquals(
                "openshift/ose-cluster-cloud-controller-manager-operator",
                adjusted.getMetadata().getComponent().getName());
        assertEquals(
                "pkg:oci/ose-cluster-cloud-controller-manager-operator@sha256%3A0897e7dcf7a971b493755010b7893b4a44800fe5032463676d016e3fe3b42d61?arch=amd64&os=linux&tag=v4.14.0-202411130434.p0.ga0b9c0d.assembly.stream.el8",
                adjusted.getMetadata().getComponent().getPurl());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
    }

    @Test
    void generatedDependenciesShouldHaveProperDependsOn() throws IOException {
        SyftImageAdjuster adjuster = createDefaultAdjuster();

        assertEquals(7, bom.getComponents().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        assertEquals(16, bom.getComponents().size());
        // Main component + all of it's components
        assertEquals(16, adjusted.getDependencies().size());
        // Main component dependencies
        assertEquals(15, adjusted.getDependencies().get(0).getDependencies().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
    }

    @Test
    void depsShouldPointToComponents() throws Exception {
        SyftImageAdjuster adjuster = new SyftImageAdjuster(tmpDir, List.of(), true, null, null);

        this.bom = SbomUtils.fromString(TestResources.asString("boms/shaded.json"));

        assertNotNull(bom);
        assertEquals(459, bom.getComponents().size());
        assertEquals(294, bom.getDependencies().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);
        // One component added (image) at position 0, one component removed (operating system), size is the same as
        // before
        assertEquals(459, adjusted.getComponents().size());
        assertEquals(459, adjusted.getDependencies().size());
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());

        for (Dependency d : bom.getDependencies()) {
            if (bom.getComponents().stream().filter(c -> c.getBomRef().equals(d.getRef())).findAny().isEmpty()) {
                throw new Exception("The dependency " + d.getRef() + " does not have a related component!");
            }
        }
    }

    // https://issues.redhat.com/browse/SBOMER-197
    @Test
    void metadataComponentShouldBeBareRepresentationOfMainComponent() throws IOException {
        SyftImageAdjuster adjuster = new SyftImageAdjuster(
                tmpDir,
                null,
                true,
                sourcesManifestPath,
                sourcesMetadataPath);

        assertFalse(bom.getMetadata().getProperties().isEmpty());

        Bom adjusted = adjuster.adjust(bom);

        Component metadataComponent = adjusted.getMetadata().getComponent();

        // Has purl
        assertEquals(
                "pkg:oci/ose-cluster-cloud-controller-manager-operator@sha256%3A0897e7dcf7a971b493755010b7893b4a44800fe5032463676d016e3fe3b42d61?arch=amd64&os=linux&tag=v4.14.0-202411130434.p0.ga0b9c0d.assembly.stream.el8",
                metadataComponent.getPurl());
        // Has type
        assertEquals(Component.Type.CONTAINER, metadataComponent.getType());
        // Has name
        assertEquals("openshift/ose-cluster-cloud-controller-manager-operator", metadataComponent.getName());
        // No properties
        assertNull(metadataComponent.getProperties());
        // Has hash
        assertEquals(1, metadataComponent.getHashes().size());
        Hash hash = metadataComponent.getHashes().get(0);
        assertEquals(Hash.Algorithm.SHA_256.getSpec(), hash.getAlgorithm());
        assertEquals("0897e7dcf7a971b493755010b7893b4a44800fe5032463676d016e3fe3b42d61", hash.getValue());
        // Has identity purl
        assertEquals(1, metadataComponent.getEvidence().getIdentities().size());
        Identity identity = metadataComponent.getEvidence().getIdentities().get(0);
        assertEquals(Identity.Field.PURL, identity.getField());
        assertEquals(
                "pkg:oci/ose-cluster-cloud-controller-manager-operator@sha256%3A0897e7dcf7a971b493755010b7893b4a44800fe5032463676d016e3fe3b42d61",
                identity.getConcludedValue());

        // The main component is the first one
        Component mainComponent = adjusted.getComponents().get(0);

        assertFalse(mainComponent.getProperties().isEmpty());
        // Has purl
        assertEquals(
                "pkg:oci/ose-cluster-cloud-controller-manager-operator@sha256%3A0897e7dcf7a971b493755010b7893b4a44800fe5032463676d016e3fe3b42d61?arch=amd64&os=linux&tag=v4.14.0-202411130434.p0.ga0b9c0d.assembly.stream.el8",
                mainComponent.getPurl());
        // Has type
        assertEquals(Component.Type.CONTAINER, mainComponent.getType());
        // Has name
        assertEquals("openshift/ose-cluster-cloud-controller-manager-operator", mainComponent.getName());
        // Other things, for example bom-ref
        assertEquals(
                "pkg:oci/ose-cluster-cloud-controller-manager-operator@sha256%3A0897e7dcf7a971b493755010b7893b4a44800fe5032463676d016e3fe3b42d61?arch=amd64&os=linux&tag=v4.14.0-202411130434.p0.ga0b9c0d.assembly.stream.el8",
                mainComponent.getBomRef());

        // Is valid
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
    }

    @Test
    void removeExternalReferencesWithBadURI() throws IOException {
        SyftImageAdjuster adjuster = createDefaultAdjuster();
        final String badUrl = "https://www:redhat.com/";

        assertEquals(2, getExternalReferenceStream(bom).count());
        assertTrue(getExternalReferenceStream(bom).anyMatch(r -> badUrl.endsWith(r.getUrl())));
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(bom)).size());

        Bom adjusted = adjuster.adjust(bom);

        assertEquals(1, getExternalReferenceStream(adjusted).count());
        assertFalse(getExternalReferenceStream(adjusted).anyMatch(r -> badUrl.endsWith(r.getUrl())));
        assertEquals(0, SbomUtils.validate(SbomUtils.toJsonNode(adjusted)).size());
    }

    @Test
    void shouldAdjustVendorAndPublisher() {
        SyftImageAdjuster adjuster = createDefaultAdjuster();

        Optional<Property> bogusVendor = bom.getMetadata()
                .getProperties()
                .stream()
                .filter(property -> "syft:image:labels:vendor".equals(property.getName()))
                .findFirst();
        assertTrue(bogusVendor.isPresent());
        assertEquals("Red Hat, Inc.", bogusVendor.get().getValue());

        Optional<Component> bogusComponent = bom.getComponents()
                .stream()
                .filter(
                        component -> "pkg:rpm/redhat/subscription-manager@1.28.42-1.el8?arch=x86_64&distro=rhel-8.10&upstream=subscription-manager-1.28.42-1.el8.src.rpm"
                                .equals(component.getPurl()))
                .findFirst();
        assertTrue(bogusComponent.isPresent());
        assertEquals("Red Hat, Inc.", bogusComponent.get().getPublisher());

        Bom adjusted = adjuster.adjust(bom);

        Optional<Property> oldVendor = adjusted.getComponents()
                .get(0)
                .getProperties()
                .stream()
                .filter(property -> "syft:image:labels:vendor".equals(property.getName()))
                .findFirst();
        assertFalse(oldVendor.isPresent());

        Optional<Property> goodVendor = adjusted.getComponents()
                .get(0)
                .getProperties()
                .stream()
                .filter(property -> Constants.CONTAINER_PROPERTY_IMAGE_LABEL_VENDOR.equals(property.getName()))
                .findFirst();
        assertTrue(goodVendor.isPresent());
        assertEquals("Red Hat", goodVendor.get().getValue());

        Optional<Component> goodComponent = adjusted.getComponents()
                .stream()
                .filter(component -> "Red Hat, Inc.".equals(component.getPublisher()))
                .findFirst();
        assertFalse(goodComponent.isPresent());
    }

    @Test
    void shouldAdjustMetadataSupplier() {
        SyftImageAdjuster adjuster = createDefaultAdjuster();
        Bom adjusted = adjuster.adjust(bom);
        assertNotNull(adjusted.getMetadata().getSupplier());
        assertEquals(Constants.SUPPLIER_NAME, adjusted.getMetadata().getSupplier().getName());
    }

    @Test
    void shouldAddContainerHash() {
        SyftImageAdjuster adjuster = createDefaultAdjuster();
        assertNotNull(bom.getComponents());
        assertTrue(bom.getComponents().size() > 0);
        assertNull(bom.getComponents().get(0).getHashes());
        Bom adjusted = adjuster.adjust(bom);
        assertNotNull(adjusted.getComponents().get(0).getHashes());
        assertEquals(1, adjusted.getComponents().get(0).getHashes().size());
        Hash hash = adjusted.getComponents().get(0).getHashes().get(0);
        assertEquals(Hash.Algorithm.SHA_256.getSpec(), hash.getAlgorithm());
        assertEquals("0897e7dcf7a971b493755010b7893b4a44800fe5032463676d016e3fe3b42d61", hash.getValue());
    }

    private Stream<ExternalReference> getExternalReferenceStream(Bom bom) {
        return bom.getComponents()
                .stream()
                .map(Component::getExternalReferences)
                .filter(Objects::nonNull)
                .flatMap(Collection::stream);
    }

    @Test
    void shouldSanitizeBogusPurls() {
        String bogusPurl = "pkg:rpm/redhat/passt@0^20230222.g4ddbcb9-4.el9_2?arch=x86_64&distro=rhel-9.2&upstream=passt-0^20230222.g4ddbcb9-4.el9_2.src.rpm";

        try {
            new PackageURL(bogusPurl);
            fail("Should fail the parsing to PURL of " + bogusPurl);
        } catch (MalformedPackageURLException e) {
            // Expected
        }

        String sanitizedPurl = PurlSanitizer.sanitizePurl(bogusPurl);

        try {
            new PackageURL(sanitizedPurl);
        } catch (MalformedPackageURLException e) {
            fail("Failed parsing to PURL of sanitized " + sanitizedPurl);
        }

        assertEquals(
                "pkg:rpm/redhat/passt@0-20230222.g4ddbcb9-4.el9_2?arch=x86_64&distro=rhel-9.2&upstream=passt-0-20230222.g4ddbcb9-4.el9_2.src.rpm",
                sanitizedPurl);
    }

    @Test
    void shouldRebuildBogusPurls() {
        // Initialize the bogus component generated from Syft and verify it's not fixable, and remains unchanged
        Component component = SbomUtils
                .createComponent(null, "../", "(devel)", null, "pkg:golang/../@(devel)", Component.Type.LIBRARY);
        component.setBomRef("a02ebe2f06983d18");
        SbomUtils.addPropertyIfMissing(component, "syft:package:type", "go-module");

        // Verify that the purl is not valid
        boolean isValid = SbomUtils.isValidPurl(component.getPurl());
        assertFalse(isValid);

        // Verify that the purl cannot be sanitized
        String sanitizedPurl = SbomUtils.sanitizePurl(component.getPurl());
        assertNull(sanitizedPurl);

        // Verify that the purl can be rebuilt
        boolean isValidAfterRebuilding = SbomUtils.hasValidOrSanitizablePurl(component);
        assertTrue(isValidAfterRebuilding);
        assertTrue(SbomUtils.isValidPurl(component.getPurl()));
    }

}
