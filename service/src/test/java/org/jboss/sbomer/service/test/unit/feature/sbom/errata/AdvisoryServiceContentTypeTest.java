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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;

import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.sbomer.core.test.TestResources;
import org.jboss.sbomer.service.feature.sbom.errata.dto.Errata;
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
        assertTrue(errata.getDetails().get().hasKnownContentType());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = { "unknown" })
    void testUnknownContentTypes(String contentType) throws IOException {
        Errata errata = loadErrataWithContentType(contentType);
        assertFalse(errata.getDetails().get().hasKnownContentType());
    }

    @Test
    void testNullContentTypeElement() {
        Errata.Details details = new Errata.Details();
        details.setContentTypes(new ArrayList<>(Collections.singletonList(null)));
        assertFalse(details.hasKnownContentType());
    }
}
