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
package org.jboss.sbomer.service.test.unit.feature.sbom.errata;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.sbomer.core.test.TestResources;
import org.jboss.sbomer.service.feature.sbom.errata.dto.Errata;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataBuildList;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataBuildList.BuildItem;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataBuildList.ProductVersionEntry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Tests {@link Errata.Details#hasKnownContentType()}.
 */
class AdvisoryServiceContentTypeTest {
    private Errata loadErrataWithContentType(String contentType) throws IOException {
        String json = TestResources.asString("errata/api/erratum_unknown_content_type.json")
                .replace("\"unknown\"", "\"" + contentType + "\"");
        return ObjectMapperProvider.json().readValue(json, Errata.class);
    }

    @ParameterizedTest
    @ValueSource(strings = { "docker", "rpm", "module" })
    void testKnownContentTypes(String contentType) throws IOException {
        Errata errata = loadErrataWithContentType(contentType);
        Optional<Errata.Details> optionalDetails = errata.getDetails();
        assertTrue(optionalDetails.isPresent());
        assertTrue(optionalDetails.get().hasKnownContentType());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = { "unknown" })
    void testUnknownContentTypes(String contentType) throws IOException {
        Errata errata = loadErrataWithContentType(contentType);
        Optional<Errata.Details> optionalDetails = errata.getDetails();
        assertTrue(optionalDetails.isPresent());
        assertFalse(optionalDetails.get().hasKnownContentType());
    }

    @Test
    void testNullContentTypeElement() {
        Errata.Details details = new Errata.Details();
        details.setContentTypes(new ArrayList<>(Collections.singletonList(null)));
        assertFalse(details.hasKnownContentType());
    }

    @Test
    void testModuleBuildList() throws IOException {
        ErrataBuildList buildList = ObjectMapperProvider.json()
                .readValue(TestResources.asString("errata/api/module_build_list.json"), ErrataBuildList.class);
        Map<String, ProductVersionEntry> productVersions = buildList.getProductVersions();
        assertEquals(1, productVersions.size());
        ProductVersionEntry productVersionEntry = productVersions.get("RHEL-8.1.0.Z.MAIN+EUS");
        assertNotNull(productVersionEntry);
        assertEquals("RHEL-8.1.0.Z.MAIN+EUS", productVersionEntry.getName());
        assertEquals("Red Hat Enterprise Linux 8", productVersionEntry.getDescription());
        List<ErrataBuildList.Build> builds = productVersionEntry.getBuilds();
        assertEquals(1, builds.size());
        ErrataBuildList.Build build = builds.get(0);
        Map<String, BuildItem> buildItems = build.getBuildItems();
        assertEquals(1, buildItems.size());
        BuildItem buildItem = buildItems.get("testmodule-private_foo_rhel_8.1.0-8010020260225154026.abcdef12");
        assertNotNull(buildItem);
        assertEquals("testmodule-private_foo_rhel_8.1.0-8010020260225154026.abcdef12", buildItem.getNvr());
        assertEquals("testmodule-0:private_foo_rhel_8.1.0-8010020260225154026.abcdef12", buildItem.getNevr());
        assertEquals(1234567L, buildItem.getId());
        assertTrue(buildItem.isModule());
        assertFalse(buildItem.isSigned());
        Map<String, ErrataBuildList.VariantArch> variantArch = buildItem.getVariantArch();
        assertEquals(0, variantArch.size());
        assertEquals("foo", buildItem.getAddedBy());
    }

    @Test
    void testBuildsWithStringBrewFiles() throws IOException {
        ErrataBuildList buildList = ObjectMapperProvider.json()
                .readValue(
                        TestResources.asString("errata/release/singleContainer/errata_143793_build_list.json"),
                        ErrataBuildList.class);
        Map<String, ProductVersionEntry> productVersions = buildList.getProductVersions();
        assertEquals(1, productVersions.size());
        ProductVersionEntry productVersionEntry = productVersions.get("RHEL-8.10.0.Z.MAIN+EUS");
        assertNotNull(productVersionEntry);
        assertEquals("RHEL-8.10.0.Z.MAIN+EUS", productVersionEntry.getName());
        assertEquals("Red Hat Enterprise Linux 8", productVersionEntry.getDescription());
        List<ErrataBuildList.Build> builds = productVersionEntry.getBuilds();
        assertEquals(1, builds.size());
        ErrataBuildList.Build build = builds.get(0);
        Map<String, BuildItem> buildItems = build.getBuildItems();
        assertEquals(1, buildItems.size());
        BuildItem buildItem = buildItems.get("ruby-25-container-1-260.1733408998");
        assertNotNull(buildItem);
        assertEquals("ruby-25-container-1-260.1733408998", buildItem.getNvr());
        assertEquals("ruby-25-container-0:1-260.1733408998", buildItem.getNevr());
        assertEquals(3427623L, buildItem.getId());
        assertFalse(buildItem.isModule());
        Map<String, ErrataBuildList.VariantArch> variantArch = buildItem.getVariantArch();
        assertEquals(1, variantArch.size());
        ErrataBuildList.VariantArch arches = variantArch.get("AppStream-8.10.0.Z.MAIN.EUS");
        assertNotNull(arches);
        assertEquals(1, arches.size());
        List<ErrataBuildList.BrewFile> brewFiles = arches.get("multi");
        assertNotNull(brewFiles);
        assertEquals(4, brewFiles.size());
        ErrataBuildList.BrewFile brewFile0 = brewFiles.get(0);
        assertEquals(
                "docker-image-sha256:f9a5db5670df3e47090132d26541cd554e0405eee8094b2bdcdd46776d79d7c9.ppc64le.tar.gz",
                brewFile0.getFilename());
        assertFalse(brewFile0.isSigned());
        ErrataBuildList.BrewFile brewFile1 = brewFiles.get(1);
        assertEquals(
                "docker-image-sha256:1f0105a8deaf465b65859833e7a74b54adedec6b0446a602b12b70cbfb47dfa7.aarch64.tar.gz",
                brewFile1.getFilename());
        assertFalse(brewFile1.isSigned());
        ErrataBuildList.BrewFile brewFile2 = brewFiles.get(2);
        assertEquals(
                "docker-image-sha256:f57ab86c6570e7ec9b08bd7dbbc31a112bef053b9f6b05766e49b30f7d1b50a1.s390x.tar.gz",
                brewFile2.getFilename());
        assertFalse(brewFile2.isSigned());
        ErrataBuildList.BrewFile brewFile3 = brewFiles.get(3);
        assertEquals(
                "docker-image-sha256:3c11044b4f4dd3ce9f3e4d2ac3780d53a2dc3c0009ac4adcfbab0419e02f971f.x86_64.tar.gz",
                brewFile3.getFilename());
        assertFalse(brewFile3.isSigned());
        assertEquals("botas/pnt-devops-rad-jenkins.rhev-ci-vms.eng.rdu2.redhat.com", buildItem.getAddedBy());
        assertFalse(buildItem.isSigned());
        assertNull(buildItem.getSigKey());
    }

    @Test
    void testBuildsWithSigKey() throws IOException {
        ErrataBuildList buildList = ObjectMapperProvider.json()
                .readValue(TestResources.asString("errata/api/builds_with_sig_key.json"), ErrataBuildList.class);
        Map<String, ProductVersionEntry> productVersions = buildList.getProductVersions();
        assertEquals(1, productVersions.size());
        ProductVersionEntry productVersionEntry = productVersions.get("RHEL-7.1.Z");
        assertNotNull(productVersionEntry);
        List<ErrataBuildList.Build> builds = productVersionEntry.getBuilds();
        assertEquals(1, builds.size());
        ErrataBuildList.Build build = builds.get(0);
        Map<String, BuildItem> buildItems = build.getBuildItems();
        assertEquals(1, buildItems.size());
        BuildItem buildItem = buildItems.get("rhel-server-docker-7.1-3");
        assertNotNull(buildItem);
        assertNull(buildItem.getAddedBy());
        assertEquals(123456L, buildItem.getId());
        assertFalse(buildItem.isModule());
        assertTrue(buildItem.isSigned());
        assertEquals("rhel-server-docker-0:7.1-3", buildItem.getNevr());
        assertEquals("rhel-server-docker-7.1-3", buildItem.getNvr());
        Map<String, ErrataBuildList.VariantArch> variantArch = buildItem.getVariantArch();
        assertEquals(1, variantArch.size());
        assertFalse(variantArch.containsKey("sig_key"));
        ErrataBuildList.VariantArch arches = variantArch.get("7Server-7.1.Z");
        assertNotNull(arches);
        assertEquals(1, arches.size());
        List<ErrataBuildList.BrewFile> brewFiles = arches.get("x86_64");
        assertNotNull(brewFiles);
        assertEquals(1, brewFiles.size());
        ErrataBuildList.BrewFile brewFile = brewFiles.get(0);
        assertEquals("rhel-server-docker-7.1-3.x86_64.tar.gz", brewFile.getFilename());
        assertFalse(brewFile.isSigned());
        ErrataBuildList.SigKey buildSigKey = buildItem.getSigKey();
        assertNotNull(buildSigKey);
        assertEquals("abcdef12", buildSigKey.getKeyid());
        assertEquals("sigkey1", buildSigKey.getName());
        ErrataBuildList.SigKey containerSigKey = productVersionEntry.getContainerSigKey();
        assertNotNull(containerSigKey);
        assertEquals("abcdef12", containerSigKey.getKeyid());
        assertEquals("sigkey1", containerSigKey.getName());
        ErrataBuildList.SigKey defaultSigKey = productVersionEntry.getDefaultSigKey();
        assertNotNull(defaultSigKey);
        assertEquals("abcdef12", defaultSigKey.getKeyid());
        assertEquals("sigkey1", defaultSigKey.getName());
        assertEquals("RHEL-7.1.Z", productVersionEntry.getDescription());
        ErrataBuildList.SigKey imaSigKey = productVersionEntry.getImaSigKey();
        assertNotNull(imaSigKey);
        assertEquals("abcdef34", imaSigKey.getKeyid());
        assertEquals("imasigkey", imaSigKey.getName());
        assertEquals("RHEL-7.1.Z", productVersionEntry.getName());
    }
}
