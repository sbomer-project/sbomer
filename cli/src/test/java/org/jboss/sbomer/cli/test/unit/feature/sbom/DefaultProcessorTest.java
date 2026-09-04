package org.jboss.sbomer.cli.test.unit.feature.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.model.Ancestors;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.ExternalReference.Type;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Pedigree;
import org.jboss.pnc.build.finder.core.BuildConfig;
import org.jboss.pnc.dto.Artifact;
import org.jboss.pnc.dto.Build;
import org.jboss.pnc.dto.BuildConfigurationRevisionRef;
import org.jboss.pnc.enums.BuildType;
import org.jboss.sbomer.cli.feature.sbom.client.RemoteSource;
import org.jboss.sbomer.cli.feature.sbom.processor.DefaultProcessor;
import org.jboss.sbomer.cli.feature.sbom.service.KojiService;
import org.jboss.sbomer.core.features.sbom.Constants;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.core.pnc.PncService;
import org.jboss.sbomer.core.test.TestResources;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.redhat.red.build.koji.KojiClientException;
import com.redhat.red.build.koji.model.xmlrpc.KojiBuildInfo;

class DefaultProcessorTest {
    private static final ObjectMapper OBJECT_MAPPER = ObjectMapperProvider.json();

    @Test
    void testProcessingWhenNoDataIsAvailable() throws IOException {
        PncService pncServiceMock = Mockito.mock(PncService.class);
        KojiService kojiServiceMock = Mockito.mock(KojiService.class);

        DefaultProcessor defaultProcessor = new DefaultProcessor(pncServiceMock, kojiServiceMock);

        Bom bom = SbomUtils.fromString(TestResources.asString("boms/image-after-adjustments.json"));
        Bom processed = defaultProcessor.process(bom);

        assertEquals(192, processed.getComponents().size());
    }

    @Test
    void testAddBrewInfo() throws IOException, KojiClientException {
        PncService pncServiceMock = Mockito.mock(PncService.class);
        KojiService kojiServiceMock = Mockito.mock(KojiService.class);

        KojiBuildInfo kojiBuildInfo = new KojiBuildInfo();
        kojiBuildInfo.setId(12345);
        kojiBuildInfo.setSource("https://git.com/repo#hash");

        BuildConfig buildConfig = new BuildConfig();
        buildConfig.setKojiWebURL(new URL("https://koji.web"));

        when(kojiServiceMock.getConfig()).thenReturn(buildConfig);
        when(kojiServiceMock.findBuild("amqstreams-console-ui-container-2.7.0-8.1718294415")).thenReturn(kojiBuildInfo);

        DefaultProcessor defaultProcessor = new DefaultProcessor(pncServiceMock, kojiServiceMock);

        Bom bom = SbomUtils.fromString(TestResources.asString("boms/image-after-adjustments.json"));
        Bom processed = defaultProcessor.process(bom);

        assertEquals(192, processed.getComponents().size());

        Component mainComponent = processed.getComponents().get(0);

        assertEquals("Red Hat", mainComponent.getSupplier().getName());
        assertEquals("Red Hat", mainComponent.getPublisher());

        ExternalReference buildSystem = SbomUtils.getExternalReferences(mainComponent, Type.BUILD_SYSTEM).get(0);

        assertEquals("https://koji.web/buildinfo?buildID=12345", buildSystem.getUrl());
        assertEquals("brew-build-id", buildSystem.getComment());

        assertEquals(
                "https://git.com/repo#hash",
                SbomUtils.getExternalReferences(mainComponent, Type.VCS).get(0).getUrl());

        Pedigree pedigree = mainComponent.getPedigree();
        assertNotNull(pedigree);
        Ancestors ancestors = pedigree.getAncestors();
        assertNotNull(ancestors);
        List<Component> components = ancestors.getComponents();
        assertNotNull(components);
        assertEquals(1, components.size());
        Component component = components.get(0);
        assertEquals(
                "pkg:generic/git.com/repo@hash?vcs_url=git%2Bhttps%3A%2F%2Fgit.com%2Frepo%40hash",
                component.getPurl());
    }

    @Test
    void testAddBrewInfoForRpm() throws IOException, KojiClientException {
        PncService pncServiceMock = Mockito.mock(PncService.class);
        KojiService kojiServiceMock = Mockito.mock(KojiService.class);

        KojiBuildInfo kojiBuildInfo = new KojiBuildInfo();
        kojiBuildInfo.setId(12345);
        kojiBuildInfo.setSource("https://git.com/repo#hash");

        BuildConfig buildConfig = new BuildConfig();
        buildConfig.setKojiWebURL(new URL("https://koji.web"));

        when(kojiServiceMock.getConfig()).thenReturn(buildConfig);
        when(kojiServiceMock.findBuildByRPM("audit-libs-3.0.7-103.el9.x86_64")).thenReturn(kojiBuildInfo);

        DefaultProcessor defaultProcessor = new DefaultProcessor(pncServiceMock, kojiServiceMock);

        Bom bom = SbomUtils.fromString(TestResources.asString("boms/image-after-adjustments.json"));
        Bom processed = defaultProcessor.process(bom);

        assertEquals(192, processed.getComponents().size());

        Component rpmComponent = SbomUtils
                .findComponentWithPurl("pkg:rpm/redhat/audit-libs@3.0.7-103.el9?arch=x86_64", processed)
                .orElseThrow();

        assertNotNull(rpmComponent.getSupplier());
        assertEquals("Red Hat", rpmComponent.getSupplier().getName());
        assertEquals("Red Hat", rpmComponent.getPublisher());

        ExternalReference buildSystem = SbomUtils.getExternalReferences(rpmComponent, Type.BUILD_SYSTEM).get(0);

        assertEquals("https://koji.web/buildinfo?buildID=12345", buildSystem.getUrl());
        assertEquals("brew-build-id", buildSystem.getComment());

        assertEquals(
                "https://git.com/repo#hash",
                SbomUtils.getExternalReferences(rpmComponent, Type.VCS).get(0).getUrl());

        Pedigree pedigree = rpmComponent.getPedigree();
        assertNotNull(pedigree);
        Ancestors ancestors = pedigree.getAncestors();
        assertNotNull(ancestors);
        List<Component> components = ancestors.getComponents();
        assertNotNull(components);
        assertEquals(1, components.size());
        Component component = components.get(0);
        assertEquals(
                "pkg:generic/git.com/repo@hash?vcs_url=git%2Bhttps%3A%2F%2Fgit.com%2Frepo%40hash",
                component.getPurl());
    }

    @Test
    void testUpdateComponentAndDependency() throws IOException {
        PncService pncServiceMock = Mockito.mock(PncService.class);
        KojiService kojiServiceMock = Mockito.mock(KojiService.class);

        Artifact artifact = Artifact.builder()
                .purl(
                        "pkg:generic/gradle-wrapper.jar?checksum=sha256%3Ae996d452d2645e70c01c11143ca2d3742734a28da2bf61f25c82bdc288c9e637")
                .sha1("23a1590b048918cb655153298462fe64d284cb78")
                .build();

        when(pncServiceMock.getArtifact(null, Optional.empty(), Optional.of(artifact.getSha1()), Optional.empty()))
                .thenReturn(artifact);

        DefaultProcessor defaultProcessor = new DefaultProcessor(pncServiceMock, kojiServiceMock);

        Bom bom = SbomUtils.fromString(TestResources.asString("boms/image-after-adjustments.json"));
        Component component = SbomUtils.createComponent(
                null,
                "gradle-wrapper",
                "UNKNOWN",
                null,
                "pkg:maven/gradle-wrapper/gradle-wrapper?type=jar",
                Component.Type.LIBRARY);
        component.addHash(new Hash(Hash.Algorithm.SHA1, artifact.getSha1()));
        bom.addComponent(component);
        Dependency dependency = SbomUtils.createDependency(component.getBomRef());
        bom.addDependency(dependency);

        Bom processed = defaultProcessor.process(bom);

        Component updatedComponent = SbomUtils.findComponentWithPurl(artifact.getPurl(), processed).orElseThrow();
        Dependency updatedDependency = getDependency(artifact.getPurl(), processed.getDependencies()).orElseThrow();

        assertEquals(193, processed.getComponents().size());
        assertEquals(193, processed.getDependencies().size());
        assertEquals(artifact.getPurl(), updatedComponent.getBomRef());
        assertEquals(artifact.getPurl(), updatedComponent.getPurl());
        assertEquals(component.getName(), updatedComponent.getName());
        assertEquals(artifact.getPurl(), updatedDependency.getRef());
    }

    @Test
    void testAddMrrcWithRelocatedPurl() throws IOException, MalformedPackageURLException {
        PncService pncServiceMock = Mockito.mock(PncService.class);
        KojiService kojiServiceMock = Mockito.mock(KojiService.class);
        PackageURL packageURL = new PackageURL("pkg:maven/org.apache.logging.log4j/log4j?type=pom");

        // The original PURL is upstream, but the PNC artifact sha1 matches a redhat version
        // Cause the PURL lookup to miss and return the redhat version
        String version = "2.19.0.redhat-00001";
        String sha1 = "6eb3200cd599d4d4b57f467f3f909890a094e7fa";
        Artifact artifact = Artifact.builder()
                .purl(packageURL.toBuilder().withVersion(version).build().toString())
                .sha1(sha1)
                .build();
        when(pncServiceMock.getArtifact(null, Optional.empty(), Optional.of(artifact.getSha1()), Optional.empty()))
                .thenReturn(artifact);
        DefaultProcessor defaultProcessor = new DefaultProcessor(pncServiceMock, kojiServiceMock);
        String upstreamVersion = version.replaceAll("[.-]redhat-\\d+$", StringUtils.EMPTY);
        String upstreamPurl = packageURL.toBuilder().withVersion(upstreamVersion).build().toString();

        // First case: a component purl that was relocated to the upstream version, but matches a redhat artifact by
        // sha1, should match as redhat and thus gain the MRRC qualifier
        Bom bom = SbomUtils.fromString(TestResources.asString("boms/image-after-adjustments.json"));
        assertNotNull(bom);
        Component component = SbomUtils.createComponent(
                packageURL.getNamespace(),
                packageURL.getName(),
                version,
                null,
                upstreamPurl,
                Component.Type.LIBRARY);
        component.addHash(new Hash(Hash.Algorithm.SHA1, artifact.getSha1()));
        bom.addComponent(component);
        Bom processed = defaultProcessor.process(bom);
        Component updatedComponent = SbomUtils.findComponentWithPurl(artifact.getPurl(), processed).orElseThrow();
        List<String> distributionUrls = SbomUtils.getExternalReferences(updatedComponent, Type.DISTRIBUTION)
                .stream()
                .map(ExternalReference::getUrl)
                .toList();

        // Check that the redhat rebuild was recognized and its metadata was enriched with exactly the MRRC URL
        assertEquals(List.of(Constants.MRRC_URL), distributionUrls);

        // Second case: an upstream component purl should be left alone
        Bom bom2 = SbomUtils.fromString(TestResources.asString("boms/image-after-adjustments.json"));
        assertNotNull(bom2);
        Component upstreamComponent = SbomUtils.createComponent(
                packageURL.getNamespace(),
                packageURL.getName(),
                upstreamVersion,
                null,
                upstreamPurl,
                Component.Type.LIBRARY);
        bom2.addComponent(upstreamComponent);

        Bom processedSecond = defaultProcessor.process(bom2);

        // Check that the upstream purl is still there
        assertTrue(SbomUtils.findComponentWithPurl(upstreamPurl, processedSecond).isPresent());
    }

    @Test
    void testAddMissingNpmDependencies() throws IOException {
        DefaultProcessor defaultProcessor = mockForAddMissingNpmDependencies();

        // With
        Bom bom = SbomUtils.fromString(TestResources.asString("boms/pnc-build.json"));
        assertNotNull(bom);
        Optional<Component> missingComponent = SbomUtils.findComponentWithPurl("pkg:npm/once@1.4.0", bom);
        Optional<Dependency> missingDependency = getDependency("pkg:npm/once@1.4.0", bom.getDependencies());

        assertTrue(missingComponent.isEmpty());
        assertTrue(missingDependency.isEmpty());
        assertEquals(8, bom.getComponents().size());

        // When
        Bom processed = defaultProcessor.process(bom);

        // Then
        assertEquals(11, processed.getComponents().size());
        verifyAddedNpmDependencies(processed);
    }

    private static DefaultProcessor mockForAddMissingNpmDependencies() throws IOException {
        PncService pncServiceMock = Mockito.mock(PncService.class);
        KojiService kojiServiceMock = Mockito.mock(KojiService.class);

        List<Artifact> artifacts = OBJECT_MAPPER
                .readValue(TestResources.asString("pnc/npmDependencies.json"), new TypeReference<>() {
                });

        Build build = Build.builder()
                .id("BALVSAEVTGYAY")
                .buildConfigRevision(BuildConfigurationRevisionRef.refBuilder().buildType(BuildType.MVN).build())
                .build();

        when(pncServiceMock.getApiUrl()).thenReturn("pnc.example.com");
        when(pncServiceMock.getBuild("BALVSAEVTGYAY")).thenReturn(build);
        when(pncServiceMock.getNPMDependencies("BALVSAEVTGYAY")).thenReturn(artifacts);

        return new DefaultProcessor(pncServiceMock, kojiServiceMock);
    }

    private static void verifyAddedNpmDependencies(Bom processed) {
        Dependency mainDependency = getDependency(
                "pkg:maven/org.keycloak/keycloak-parent@24.0.6.redhat-00001?type=pom",
                processed.getDependencies()).orElseThrow();

        Component componentOnce = SbomUtils.findComponentWithPurl("pkg:npm/once@1.4.0", processed).orElseThrow();
        ExternalReference onceArtifact = SbomUtils
                .getExternalReferences(componentOnce, Type.BUILD_SYSTEM, Constants.SBOM_RED_HAT_PNC_ARTIFACT_ID)
                .get(0);
        assertEquals("https://pnc.example.com/pnc-rest/v2/artifacts/2160610", onceArtifact.getUrl());
        assertTrue(getDependency("pkg:npm/once@1.4.0", mainDependency.getDependencies()).isPresent());
        assertTrue(getDependency("pkg:npm/once@1.4.0", processed.getDependencies()).isPresent());
        assertNull(componentOnce.getGroup());
        assertEquals("once", componentOnce.getName());
        assertEquals("1.4.0", componentOnce.getVersion());

        Component componentKogito = SbomUtils
                .findComponentWithPurl("pkg:npm/%40redhat/kogito-tooling-keyboard-shortcuts@0.9.0-2", processed)
                .orElseThrow();
        assertNotNull(componentKogito.getSupplier());
        assertEquals("Red Hat", componentKogito.getSupplier().getName());
        assertEquals("Red Hat", componentKogito.getPublisher());
        ExternalReference buildSystem = SbomUtils
                .getExternalReferences(componentKogito, Type.BUILD_SYSTEM, Constants.SBOM_RED_HAT_PNC_BUILD_ID)
                .get(0);
        assertEquals("https://pnc.example.com/pnc-rest/v2/builds/96015", buildSystem.getUrl());
        assertEquals(
                "https://github.com/kiegroup/kogito-tooling.git",
                SbomUtils.getExternalReferences(componentKogito, Type.VCS).get(0).getUrl());
        Pedigree pedigree = componentKogito.getPedigree();
        assertNotNull(pedigree);
        Ancestors ancestors = pedigree.getAncestors();
        assertNotNull(ancestors);
        List<Component> components = ancestors.getComponents();
        assertNotNull(components);
        assertEquals(1, components.size());
        Component commit = components.get(0);
        assertEquals(
                "pkg:generic/git.example.com/gerrit/kiegroup/kogito-tooling@88c1a77824c7bf0b636f24b4bde2b87c0b38d8a1?vcs_url=git%2Bhttp%3A%2F%2Fgit.example.com%2Fgerrit%2Fkiegroup%2Fkogito-tooling.git%400.9.0",
                commit.getPurl());
        assertTrue(
                getDependency(
                        "pkg:npm/%40redhat/kogito-tooling-keyboard-shortcuts@0.9.0-2",
                        mainDependency.getDependencies()).isPresent());
        assertTrue(
                getDependency(
                        "pkg:npm/%40redhat/kogito-tooling-keyboard-shortcuts@0.9.0-2",
                        processed.getDependencies()).isPresent());
        assertEquals("@redhat", componentKogito.getGroup());
        assertEquals("kogito-tooling-keyboard-shortcuts", componentKogito.getName());
        assertEquals("0.9.0-2", componentKogito.getVersion());
    }

    private static Optional<Dependency> getDependency(String ref, List<Dependency> dependencies) {
        return dependencies.stream().filter(d -> d.getRef().equals(ref)).findFirst();
    }

    @Test
    void baseTest() throws IOException {
        Bom bom = SbomUtils.fromString(TestResources.asString("boms/adjusted.json"));

        PncService pncServiceMock = Mockito.mock(PncService.class);
        KojiService kojiServiceMock = Mockito.mock(KojiService.class);

        DefaultProcessor defaultProcessor = new DefaultProcessor(pncServiceMock, kojiServiceMock);

        assertNotNull(bom);
        assertEquals(459, bom.getComponents().size());
        assertEquals(459, bom.getDependencies().size());

        defaultProcessor.process(bom);

        assertEquals(459, bom.getComponents().size());
        assertEquals(459, bom.getDependencies().size());
    }

    @Test
    void testAddRemoteSourcePedigree() throws IOException, KojiClientException {
        PncService pncServiceMock = Mockito.mock(PncService.class);
        KojiService kojiServiceMock = Mockito.mock(KojiService.class);

        KojiBuildInfo kojiBuildInfo = new KojiBuildInfo();
        kojiBuildInfo.setId(12345);

        BuildConfig buildConfig = new BuildConfig();
        buildConfig.setKojiWebURL(new URL("https://koji.web"));

        RemoteSource remoteSource1 = new RemoteSource();
        remoteSource1.setRepo("https://github.com/stackrox/stackrox.git");
        remoteSource1.setRef("49cc2ba8faecefb5654462814c00501076837483");

        RemoteSource remoteSource2 = new RemoteSource();
        remoteSource2.setRepo("https://github.com/facebook/rocksdb.git");
        remoteSource2.setRef("0915c99f01b46f50af8e02da8b6528156f584b7c");

        when(kojiServiceMock.getConfig()).thenReturn(buildConfig);
        when(kojiServiceMock.findBuild("amqstreams-console-ui-container-2.7.0-8.1718294415")).thenReturn(kojiBuildInfo);
        when(kojiServiceMock.downloadRemoteSources(kojiBuildInfo)).thenReturn(List.of(remoteSource1, remoteSource2));

        DefaultProcessor defaultProcessor = new DefaultProcessor(pncServiceMock, kojiServiceMock);

        Bom bom = SbomUtils.fromString(TestResources.asString("boms/image-after-adjustments.json"));
        Bom processed = defaultProcessor.process(bom);

        Component mainComponent = processed.getComponents().get(0);
        Pedigree pedigree = mainComponent.getPedigree();
        assertNotNull(pedigree);
        Ancestors ancestors = pedigree.getAncestors();
        assertNotNull(ancestors);
        List<Component> components = ancestors.getComponents();
        assertNotNull(components);
        assertEquals(2, components.size());

        Component ancestor1 = components.get(0);
        assertEquals(Component.Type.LIBRARY, ancestor1.getType());
        assertEquals("stackrox", ancestor1.getName());
        assertEquals(
                "pkg:generic/github.com/stackrox/stackrox@49cc2ba8faecefb5654462814c00501076837483?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fstackrox%2Fstackrox.git",
                ancestor1.getPurl());

        Component ancestor2 = components.get(1);
        assertEquals(Component.Type.LIBRARY, ancestor2.getType());
        assertEquals("rocksdb", ancestor2.getName());
        assertEquals(
                "pkg:generic/github.com/facebook/rocksdb@0915c99f01b46f50af8e02da8b6528156f584b7c?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Ffacebook%2Frocksdb.git",
                ancestor2.getPurl());

        List<ExternalReference> vcsRefs = mainComponent.getExternalReferences()
                .stream()
                .filter(ref -> ref.getType() == ExternalReference.Type.VCS)
                .toList();
        assertEquals(2, vcsRefs.size());

        ExternalReference vcsRef1 = vcsRefs.get(0);
        assertEquals("https://github.com/stackrox/stackrox.git", vcsRef1.getUrl());

        ExternalReference vcsRef2 = vcsRefs.get(1);
        assertEquals("https://github.com/facebook/rocksdb.git", vcsRef2.getUrl());
    }
}
