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
package org.jboss.sbomer.core.features.sbom.validation;

import static org.jboss.sbomer.core.features.sbom.utils.SbomUtils.schemaVersion;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.cyclonedx.exception.ParseException;
import org.hibernate.validator.constraintvalidation.HibernateConstraintValidatorContext;

import com.fasterxml.jackson.databind.JsonNode;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class CycloneDxBomValidator implements ConstraintValidator<CycloneDxBom, JsonNode> {

    @Override
    public boolean isValid(JsonNode value, ConstraintValidatorContext context) {
        if (value == null) {
            return true;
        }

        List<ParseException> exceptions;

        try {
            exceptions = new SbomerJsonParser().validate(
                    value.isTextual() ? value.textValue().getBytes() : value.toString().getBytes(),
                    schemaVersion());

            if (exceptions.isEmpty()) {
                return true;
            }

        } catch (IOException e) {
            setPayload(context, Collections.singletonList("sbom: unable to parse as CycloneDX format"));

            return false;
        }

        setPayload(context, exceptions.stream().map(cv -> "sbom" + cv.getMessage().substring(1)).toList());

        return false;
    }

    private void setPayload(ConstraintValidatorContext context, List<String> errors) {
        if (context instanceof HibernateConstraintValidatorContext) {
            HibernateConstraintValidatorContext hcvc = context.unwrap(HibernateConstraintValidatorContext.class);
            hcvc.addExpressionVariable("errors", String.join(", ", errors));
            hcvc.withDynamicPayload(errors);
        }
    }

}
