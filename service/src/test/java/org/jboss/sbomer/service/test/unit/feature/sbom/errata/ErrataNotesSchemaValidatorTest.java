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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;

import org.jboss.sbomer.core.SchemaValidator.ValidationResult;
import org.jboss.sbomer.core.test.TestResources;
import org.jboss.sbomer.service.feature.sbom.errata.ErrataNotesSchemaValidator;
import org.jboss.sbomer.service.feature.sbom.errata.dto.Errata;
import org.junit.jupiter.api.Test;

class ErrataNotesSchemaValidatorTest {
    private static final String BASE_PATH = "errata/notes/amq-clients-notes";

    private final ErrataNotesSchemaValidator validator = new ErrataNotesSchemaValidator();

    private static Errata newErrata(String notes) {
        Errata.Content content = new Errata.Content();
        content.setNotes(notes);
        Errata.WrappedContent wrappedContent = new Errata.WrappedContent();
        wrappedContent.setContent(content);
        Errata errata = new Errata();
        errata.setContent(wrappedContent);
        return errata;
    }

    @Test
    void validNotes() throws IOException {
        String notes = TestResources.asString(BASE_PATH + ".json");
        ValidationResult result = validator.validate(newErrata(notes));
        assertTrue(result.isValid(), () -> "Expected valid result, but got errors: " + result.getErrors());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void invalidNotes() throws IOException {
        String notes = TestResources.asString(BASE_PATH + "-invalid.json");
        ValidationResult result = validator.validate(newErrata(notes));
        assertFalse(result.isValid());
        List<String> errors = result.getErrors();
        assertEquals(1, errors.size());
        assertEquals("#: Instance does not match exactly one subschema (2 matches)", errors.get(0));
    }
}
