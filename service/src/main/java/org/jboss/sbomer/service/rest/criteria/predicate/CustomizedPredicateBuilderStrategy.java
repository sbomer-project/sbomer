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
package org.jboss.sbomer.service.rest.criteria.predicate;

import java.util.regex.Pattern;

import org.jboss.sbomer.core.features.sbom.enums.GenerationResult;
import org.jboss.sbomer.service.feature.sbom.k8s.model.SbomGenerationStatus;
import org.jboss.sbomer.service.rest.criteria.AbstractCriteriaAwareRepository;

import com.github.tennaito.rsql.builder.BuilderTools;
import com.github.tennaito.rsql.jpa.PredicateBuilder;
import com.github.tennaito.rsql.jpa.PredicateBuilderStrategy;
import com.github.tennaito.rsql.misc.EntityManagerAdapter;

import cz.jirutka.rsql.parser.ast.ComparisonNode;
import cz.jirutka.rsql.parser.ast.ComparisonOperator;
import cz.jirutka.rsql.parser.ast.Node;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.From;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;

public class CustomizedPredicateBuilderStrategy implements PredicateBuilderStrategy {
    private static final char ESCAPE_CHAR = '\\';

    private static final String ESCAPE_STRING = String.valueOf(ESCAPE_CHAR);

    private static final String ESCAPED_ESCAPE = ESCAPE_STRING + ESCAPE_STRING;

    private static final String UNDERSCORE = "_";

    private static final String PERCENT = "%";

    private static final String ESCAPED_UNDERSCORE = ESCAPE_STRING + UNDERSCORE;

    private static final String WILDCARD_CHAR = "*";

    private static final Pattern WILDCARD_PATTERN = Pattern.compile("[" + WILDCARD_CHAR + "\\s]+");

    @Override
    public <T> Predicate createPredicate(
            Node node,
            From root,
            Class<T> entity,
            EntityManagerAdapter ema,
            BuilderTools tools) throws IllegalArgumentException {

        ComparisonNode cn = (ComparisonNode) node;
        ComparisonOperator operator = cn.getOperator();
        CriteriaBuilder builder = ema.getCriteriaBuilder();

        Path path = PredicateBuilder.findPropertyPath(cn.getSelector(), root, ema, tools);

        if (operator.equals(AbstractCriteriaAwareRepository.IS_NULL)) {
            Object argument = cn.getArguments().get(0);
            if (argument instanceof String strArg) {
                if (Boolean.parseBoolean(strArg)) {
                    return builder.isNull(path);
                } else {
                    return builder.isNotNull(path);
                }
            }
        } else if (operator.equals(AbstractCriteriaAwareRepository.IS_EQUAL)) {
            Object argument = cn.getArguments().get(0);
            if (argument instanceof String strArg) {

                if (Enum.class.isAssignableFrom(path.getJavaType())) {
                    if (path.getJavaType().equals(GenerationResult.class)) {
                        try {
                            GenerationResult result = GenerationResult.valueOf(strArg.toUpperCase());
                            return builder.equal(path, result);
                        } catch (IllegalArgumentException ex) {
                            throw new IllegalArgumentException("Unknown value: " + argument + " for GenerationResult");
                        }
                    } else if (path.getJavaType().equals(SbomGenerationStatus.class)) {
                        try {
                            SbomGenerationStatus status = SbomGenerationStatus.fromName(strArg);
                            return builder.equal(path, status);
                        } catch (IllegalArgumentException ex) {
                            throw new IllegalArgumentException(
                                    "Unknown value: " + argument + " for SbomGenerationStatus");
                        }
                    }
                }
                return builder.equal(path, argument);
            } else {
                return builder.isNull(path);
            }
        } else if (operator.equals(AbstractCriteriaAwareRepository.IS_LIKE)) {
            Object argument = cn.getArguments().get(0);
            if (argument instanceof String strArg) {
                if (Enum.class.isAssignableFrom(path.getJavaType())) {
                    throw new IllegalArgumentException("Cannot use like predicate on Enum fields");
                }
                return builder
                        .like(builder.lower(path), preprocessLikeOperatorArgument(strArg.toLowerCase()), ESCAPE_CHAR);
            } else {
                return builder.isNull(path);
            }
        }

        throw new IllegalArgumentException("Unknown operator: " + cn.getOperator());
    }

    private String preprocessLikeOperatorArgument(String argument) {
        String escaped = argument.trim().replace(ESCAPE_STRING, ESCAPED_ESCAPE).replace(UNDERSCORE, ESCAPED_UNDERSCORE);
        return WILDCARD_PATTERN.matcher(escaped).replaceAll(PERCENT);
    }
}
