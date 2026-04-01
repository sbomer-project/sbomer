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
    void testModuleBuildListParsing() throws IOException {
        ErrataBuildList buildList = ObjectMapperProvider.json()
                .readValue(TestResources.asString("errata/api/module_build_list.json"), ErrataBuildList.class);
        assertEquals(1, buildList.getProductVersions().size());
        ProductVersionEntry productVersionEntry = buildList.getProductVersions().get("RHEL-8.1.0.Z.MAIN+EUS");
        assertNotNull(productVersionEntry);
        assertEquals("RHEL-8.1.0.Z.MAIN+EUS", productVersionEntry.getName());
        assertEquals("Red Hat Enterprise Linux 8", productVersionEntry.getDescription());
        List<ErrataBuildList.Build> builds = productVersionEntry.getBuilds();
        assertEquals(1, builds.size());
        ErrataBuildList.Build build = builds.get(0);
        assertNotNull(build);
        Map<String, BuildItem> buildItems = build.getBuildItems();
        assertEquals(1, buildItems.size());
        BuildItem buildItem = buildItems.get("testmodule-private_foo_rhel_8.1.0-8010020260225154026.abcdef12");
        assertNotNull(buildItem);
        assertEquals("testmodule-private_foo_rhel_8.1.0-8010020260225154026.abcdef12", buildItem.getNvr());
        assertEquals("testmodule-0:private_foo_rhel_8.1.0-8010020260225154026.abcdef12", buildItem.getNevr());
        assertEquals(1234567L, buildItem.getId());
        assertTrue(buildItem.isModule());
        Map<String, ErrataBuildList.VariantArch> variantArch = buildItem.getVariantArch();
        assertEquals(0, variantArch.size());
        assertEquals("foo", buildItem.getAddedBy());
    }
}
