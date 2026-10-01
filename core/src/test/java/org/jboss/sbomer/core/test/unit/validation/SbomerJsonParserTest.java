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
import org.cyclonedx.parsers.JsonParser;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Guards the SPDX license override installed by
 * {@link org.jboss.sbomer.core.features.sbom.validation.SbomerJsonParser}.
 * <p>
 * The {@code cyclonedx-core-java} jar bundles an older SPDX snapshot that is missing newer identifiers (e.g.
 * {@code Artistic-dist}). The override redirects the SPDX {@code $ref} to our refreshed
 * {@code sbomer-spdx.schema.json}. If that override is reverted, or a future cyclonedx bump reinstates the stale list,
 * the first test below starts failing.
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
        licenseChoice.setLicenses(List.of(license));
        component.setLicenses(licenseChoice);

        bom.setComponents(List.of(component));

        return SbomUtils.toJsonNode(bom);
    }

    /** Validation through the override (SbomerJsonParser), via SbomUtils.validate. */
    private static List<ParseException> validateWithLicense(String licenseId) throws IOException {
        return SbomUtils.validate(bomWithLicense(licenseId));
    }

    /** Validation through the plain upstream JsonParser (stale bundled SPDX list, no override). */
    private static List<ParseException> validateWithPlainParser(String licenseId) throws IOException {
        JsonNode jsonNode = bomWithLicense(licenseId);
        return new JsonParser().validate(jsonNode.toString().getBytes(), SbomUtils.schemaVersion());
    }

    @Test
    @DisplayName("Accepts Artistic-dist, which is absent from the stale bundled SPDX snapshot")
    void shouldAcceptArtisticDistLicense() throws IOException {
        List<ParseException> errors = validateWithLicense("Artistic-dist");

        assertTrue(
                errors.isEmpty(),
                () -> "Expected no validation errors for Artistic-dist, got: "
                        + errors.stream().map(ParseException::getMessage).toList());
    }

    @Test
    @DisplayName("Still rejects a non-SPDX identifier, proving the enum is enforced (not disabled)")
    void shouldRejectBogusLicense() throws IOException {
        List<ParseException> errors = validateWithLicense("This-Is-Not-A-Real-SPDX-Id");

        assertFalse(errors.isEmpty(), "Expected a validation error for a bogus license id, got none");
    }

    @Test
    @DisplayName("The plain upstream JsonParser still rejects Artistic-dist — demonstrates the override is required")
    void plainParserStillRejectsArtisticDist() throws IOException {
        List<ParseException> errors = validateWithPlainParser("Artistic-dist");

        assertFalse(
                errors.isEmpty(),
                "Expected the plain JsonParser to reject Artistic-dist (stale bundled SPDX list). If this now passes, "
                        + "the bundled cyclonedx-core-java SPDX snapshot includes it and the override may be redundant.");
    }
}
