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
package org.jboss.sbomer.service.rest.criteria;

import static org.jboss.sbomer.service.rest.criteria.predicate.CustomizedPredicateBuilderStrategy.WILDCARD_CHAR;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jboss.pnc.common.Strings;
import org.jboss.sbomer.service.rest.criteria.predicate.CustomPredicateSortBuilder;
import org.jboss.sbomer.service.rest.criteria.predicate.CustomizedJpaPredicateSortVisitor;
import org.jboss.sbomer.service.rest.criteria.predicate.CustomizedJpaPredicateVisitor;
import org.jboss.sbomer.service.rest.criteria.predicate.CustomizedPredicateBuilderStrategy;

import com.github.tennaito.rsql.misc.EntityManagerAdapter;

import cz.jirutka.rsql.parser.RSQLParser;
import cz.jirutka.rsql.parser.ast.ComparisonOperator;
import cz.jirutka.rsql.parser.ast.Node;
import cz.jirutka.rsql.parser.ast.RSQLOperators;
import cz.jirutka.rsql.parser.ast.RSQLVisitor;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.annotation.PostConstruct;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Order;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Transactional
public abstract class AbstractCriteriaAwareRepository<T> implements PanacheRepositoryBase<T, String> {

    private static final Pattern LIKE_PATTERN = Pattern.compile("(%[a-zA-Z0-9\\s]+%)");
    private static final Pattern WHITESPACE_PATTERN = Pattern.compile("\\s");

    protected static final RSQLParser predicateParser;
    protected static final RSQLParser sortParser;

    public static final ComparisonOperator IS_NULL = new ComparisonOperator("=isnull=", "=ISNULL=");
    public static final ComparisonOperator IS_EQUAL = new ComparisonOperator("=eq=", "=EQ=");
    public static final ComparisonOperator IS_LIKE = new ComparisonOperator("=like=", "=LIKE=");

    public static final ComparisonOperator ASC = new ComparisonOperator("=asc=", true);
    public static final ComparisonOperator DESC = new ComparisonOperator("=desc=", true);

    CriteriaBuilder criteriaBuilder;
    EntityManagerAdapter entityManagerAdapter;
    Class<T> entityType;

    static {
        Set<ComparisonOperator> predicateOperators = RSQLOperators.defaultOperators();
        predicateOperators.add(IS_NULL);
        predicateOperators.add(IS_EQUAL);
        predicateOperators.add(IS_LIKE);

        predicateParser = new RSQLParser(predicateOperators);

        Set<ComparisonOperator> sortOperators = new HashSet<>();
        sortOperators.add(ASC);
        sortOperators.add(DESC);

        sortParser = new RSQLParser(sortOperators);
    }

    /**
     * Reads the total number of entities that satisfy the RSQL query.
     *
     * @param rsqlQuery RSQL query to be taken into account.
     * @return the total number of entities that satisfy the RSQL query
     */
    public Long countByRsqlQuery(String rsqlQuery) {
        CriteriaQuery<Long> criteriaQuery = criteriaBuilder.createQuery(Long.class);
        Root<T> root = criteriaQuery.from(entityType);
        criteriaQuery.select(criteriaBuilder.countDistinct(root));

        criteriaQuery = handleRsql(criteriaQuery, root, rsqlQuery);
        return getEntityManager().createQuery(criteriaQuery).getSingleResult();
    }

    protected AbstractCriteriaAwareRepository(Class<T> entityType) {
        this.entityType = entityType;
    }

    @PostConstruct
    @Transactional
    protected void init() {
        entityManagerAdapter = new EntityManagerAdapter(getEntityManager());
        criteriaBuilder = entityManagerAdapter.getCriteriaBuilder();
    }

    private String preprocessRSQL(String rsql) {
        return LIKE_PATTERN.matcher(rsql)
                .replaceAll(
                        match -> Matcher.quoteReplacement(
                                WHITESPACE_PATTERN.matcher(match.group(1))
                                        .replaceAll(Matcher.quoteReplacement(WILDCARD_CHAR))));
    }

    protected <X> CriteriaQuery<X> handleRsql(CriteriaQuery<X> query, Root<T> root, String rsqlQuery) {
        if (Strings.isEmpty(rsqlQuery)) {
            return query;
        }

        String preprocessed = preprocessRSQL(rsqlQuery);
        log.debug(
                "Applying provided RSQL query to enhance search: '{}' (preprocessed to '{}')",
                rsqlQuery,
                preprocessed);

        // Create custom implementation of RSQLVisitor, which converts nodes to predicates using
        // CustomizedPredicateBuilder or CustomizedPredicateBuilderStrategy for custom operators
        RSQLVisitor<Predicate, EntityManagerAdapter> visitor = new CustomizedJpaPredicateVisitor<X>().withRoot(root)
                .withPredicateBuilderStrategy(new CustomizedPredicateBuilderStrategy());

        // create RSQLParser with default and custom operators
        Node rootNode = predicateParser.parse(preprocessed);
        Predicate predicate = rootNode.accept(visitor, entityManagerAdapter);

        return query.where(predicate);
    }

    protected <X> CriteriaQuery<X> handleSort(CriteriaQuery<X> query, Root<T> root, String sort) {
        if (Strings.isEmpty(sort)) {
            return query;
        }

        String compliantSort = CustomPredicateSortBuilder.rsqlParserCompliantSort(sort);
        log.debug("Modified RSQL sort string from: '{}' to a RSQL parser compliant format: '{}'", sort, compliantSort);

        CustomizedJpaPredicateSortVisitor<?> sortVisitor = new CustomizedJpaPredicateSortVisitor<>(entityType)
                .withRoot(root);

        Node sortRootNode = sortParser.parse(compliantSort);
        Collection<Order> orders = sortVisitor.accept(sortRootNode, entityManagerAdapter);

        return query.orderBy(orders.toArray(new Order[0]));
    }

}
