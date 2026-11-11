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
package org.jboss.sbomer.core.test.validation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.file.Paths;
import java.util.List;
import java.util.Locale;

import org.cyclonedx.model.Bom;
import org.hibernate.validator.constraintvalidation.HibernateConstraintValidatorContext;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.core.features.sbom.validation.CycloneDxBomValidator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class CycloneDxBomValidatorTest {

    private static Locale originalLocale;

    @BeforeAll
    static void setLocale() {
        originalLocale = Locale.getDefault();
        Locale.setDefault(Locale.US);
    }

    @AfterAll
    static void resetLocale() {
        Locale.setDefault(originalLocale);
    }

    @Test
    void testBomValidation() {
        HibernateConstraintValidatorContext context = mock(HibernateConstraintValidatorContext.class);
        // ConstraintValidatorContext context = mock(HibernateConstraintValidatorContext.class);
        when(context.unwrap(HibernateConstraintValidatorContext.class)).thenReturn(context);

        Bom bom = SbomUtils.fromPath(Paths.get("src", "test", "resources", "sboms", "invalid-pedigree.json"));

        CycloneDxBomValidator validator = new CycloneDxBomValidator();

        assertFalse(validator.isValid(SbomUtils.toJsonNode(bom), context));

        verify(context, times(1)).addExpressionVariable(
                "errors",
                "/components/2/pedigree/commits/1/url: does not match the iri-reference pattern must be a valid RFC 3987 IRI-reference");
        verify(context, times(1)).withDynamicPayload(
                List.of(
                        "/components/2/pedigree/commits/1/url: does not match the iri-reference pattern must be a valid RFC 3987 IRI-reference"));

    }
}
