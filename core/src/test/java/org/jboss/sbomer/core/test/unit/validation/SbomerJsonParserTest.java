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
package org.jboss.sbomer.core.test.unit.validation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;

import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Guards the SPDX license override installed by
 * {@link org.jboss.sbomer.core.features.sbom.validation.SbomerJsonParser}.
 * <p>
 * The override remaps the SPDX {@code $ref} to a schema generated at runtime from the union of the
 * {@code java-spdx-library} license list and the list bundled in the {@code cyclonedx-core-java} jar.
 */
class SbomerJsonParserTest {

    private static JsonNode bomWithLicense(String licenseId) {
        Bom bom = SbomUtils.createBom();

        Component component = new Component();
        component.setType(Component.Type.LIBRARY);
        component.setName("test-component");
        component.setVersion("1.0.0");

        License license = new License();
        license.setId(licenseId);
        LicenseChoice licenseChoice = new LicenseChoice();
        licenseChoice.addLicense(license);
        component.setLicenses(licenseChoice);

        bom.setComponents(List.of(component));

        return SbomUtils.toJsonNode(bom);
    }

    /** Validation through the override (SbomerJsonParser), via SbomUtils.validate. */
    private static List<ParseException> validateWithLicense(String licenseId) throws IOException {
        return SbomUtils.validate(bomWithLicense(licenseId));
    }

    @Test
    @DisplayName("Accepts Artistic-dist, which is absent from SPDX license lists before 3.27.0")
    void shouldAcceptArtisticDistLicense() throws IOException {
        List<ParseException> errors = validateWithLicense("Artistic-dist");

        assertTrue(
                errors.isEmpty(),
                () -> "Expected no validation errors for Artistic-dist, got: "
                        + errors.stream().map(ParseException::getMessage).toList());
    }

    @Test
    @DisplayName("Accepts a bare SPDX license-exception id in license.id (enum is licenses UNION exceptions)")
    void shouldAcceptLicenseExceptionId() throws IOException {
        List<ParseException> errors = validateWithLicense("Classpath-exception-2.0");

        assertTrue(
                errors.isEmpty(),
                () -> "Expected no validation errors for Classpath-exception-2.0, got: "
                        + errors.stream().map(ParseException::getMessage).toList());
    }

    @Test
    @DisplayName("Still rejects a non-SPDX identifier, proving the enum is enforced (not disabled)")
    void shouldRejectBogusLicense() throws IOException {
        List<ParseException> errors = validateWithLicense("This-Is-Not-A-Real-SPDX-Id");

        assertFalse(errors.isEmpty(), "Expected a validation error for a bogus license id, got none");
    }
}
