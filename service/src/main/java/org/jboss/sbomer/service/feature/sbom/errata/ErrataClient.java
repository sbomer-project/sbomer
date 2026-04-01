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
package org.jboss.sbomer.service.feature.sbom.errata;

import static org.jboss.sbomer.core.rest.faulttolerance.Constants.ERRATA_CLIENT_DELAY;
import static org.jboss.sbomer.core.rest.faulttolerance.Constants.ERRATA_CLIENT_MAX_RETRIES;

import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import org.eclipse.microprofile.faulttolerance.Retry;
import org.eclipse.microprofile.rest.client.annotation.ClientHeaderParam;
import org.eclipse.microprofile.rest.client.annotation.RegisterProvider;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;
import org.jboss.sbomer.core.errors.ClientException;
import org.jboss.sbomer.core.errors.ForbiddenException;
import org.jboss.sbomer.core.errors.NotFoundException;
import org.jboss.sbomer.core.errors.UnauthorizedException;
import org.jboss.sbomer.core.rest.faulttolerance.RetryLogger;
import org.jboss.sbomer.service.feature.sbom.errata.dto.Errata;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataBuildList;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataCDNRepo;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataCDNRepoNormalized;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataPage;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataProduct;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataRelease;
import org.jboss.sbomer.service.feature.sbom.errata.dto.ErrataVariant;
import org.jboss.sbomer.service.feature.sbom.kerberos.ErrataKrb5ClientRequestFilter;
import org.jboss.sbomer.service.rest.otel.SpanName;
import org.jboss.sbomer.service.rest.otel.Traced;

import io.quarkus.rest.client.reactive.ClientExceptionMapper;
import io.smallrye.faulttolerance.api.BeforeRetry;
import io.smallrye.faulttolerance.api.ExponentialBackoff;
import io.smallrye.reactive.messaging.annotations.Blocking;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.validation.Valid;
import jakarta.ws.rs.BeanParam;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * A client for Errata
 */
@ApplicationScoped
@ClientHeaderParam(name = "User-Agent", value = "SBOMer")
@RegisterRestClient(configKey = "errata")
@Path("/api/v1")
@RegisterProvider(ErrataKrb5ClientRequestFilter.class)
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface ErrataClient {

    // Retrieve the advisory data, the id could be advisory id or advisory name.
    @Traced
    @SpanName("errata.get")
    @GET
    @Path("/erratum/{id}")
    @Retry(
            maxRetries = ERRATA_CLIENT_MAX_RETRIES,
            delay = ERRATA_CLIENT_DELAY,
            delayUnit = ChronoUnit.SECONDS,
            abortOn = UnauthorizedException.class)
    @ExponentialBackoff
    @BeforeRetry(RetryLogger.class)
    Errata getErratum(@PathParam("id") String erratumId);

    // Get the details of a product by its id or short name
    @Traced
    @SpanName("errata.product.get")
    @GET
    @Path("/products/{id}")
    @Retry(
            maxRetries = ERRATA_CLIENT_MAX_RETRIES,
            delay = ERRATA_CLIENT_DELAY,
            delayUnit = ChronoUnit.SECONDS,
            abortOn = UnauthorizedException.class)
    @ExponentialBackoff
    @BeforeRetry(RetryLogger.class)
    ErrataProduct getProduct(@PathParam("id") String productId);

    // Get the details of a release by its id or name
    @Traced
    @SpanName("errata.release.get")
    @GET
    @Path("/releases/{id}")
    @Retry(
            maxRetries = ERRATA_CLIENT_MAX_RETRIES,
            delay = ERRATA_CLIENT_DELAY,
            delayUnit = ChronoUnit.SECONDS,
            abortOn = UnauthorizedException.class)
    @ExponentialBackoff
    @BeforeRetry(RetryLogger.class)
    ErrataRelease getRelease(@PathParam("id") String releaseId);

    // Get the details of a variant by its name or id
    @Traced
    @SpanName("errata.variant.get")
    @GET
    @Path("/variants/{id}")
    @Retry(
            maxRetries = ERRATA_CLIENT_MAX_RETRIES,
            delay = ERRATA_CLIENT_DELAY,
            delayUnit = ChronoUnit.SECONDS,
            abortOn = UnauthorizedException.class)
    @ExponentialBackoff
    @BeforeRetry(RetryLogger.class)
    ErrataVariant getVariant(@PathParam("id") String variantId);

    // Get the details of a variant by its name or id
    @Traced
    @SpanName("errata.variants.get")
    @GET
    @Path("/variants")
    @Retry(
            maxRetries = ERRATA_CLIENT_MAX_RETRIES,
            delay = ERRATA_CLIENT_DELAY,
            delayUnit = ChronoUnit.SECONDS,
            abortOn = UnauthorizedException.class)
    @ExponentialBackoff
    @BeforeRetry(RetryLogger.class)
    ErrataPage<ErrataVariant.VariantData> getAllVariants(@Valid @BeanParam ErrataQueryParameters pageParameters);

    // Add a comment to an advisory. Example request body: {"comment": "This is my comment"}
    @Traced
    @SpanName("errata.comment.add")
    @POST
    @Path("/erratum/{id}/add_comment")
    @Retry(
            maxRetries = ERRATA_CLIENT_MAX_RETRIES,
            delay = ERRATA_CLIENT_DELAY,
            delayUnit = ChronoUnit.SECONDS,
            abortOn = UnauthorizedException.class)
    @ExponentialBackoff
    @BeforeRetry(RetryLogger.class)
    Errata addCommentToErratum(@PathParam("id") String erratumId, String comment);

    // Fetch the Brew builds list associated with an advisory
    @Traced
    @SpanName("errata.build_list.get")
    @GET
    @Path("/erratum/{id}/builds_list")
    @Retry(
            maxRetries = ERRATA_CLIENT_MAX_RETRIES,
            delay = ERRATA_CLIENT_DELAY,
            delayUnit = ChronoUnit.SECONDS,
            abortOn = UnauthorizedException.class)
    @ExponentialBackoff
    @BeforeRetry(RetryLogger.class)
    ErrataBuildList getBuildsList(@PathParam("id") String erratumId);

    // Fetch the Brew builds associated with an advisory
    @Traced
    @SpanName("errata.builds.get")
    @GET
    @Path("/erratum/{id}/builds")
    @Retry(
            maxRetries = ERRATA_CLIENT_MAX_RETRIES,
            delay = ERRATA_CLIENT_DELAY,
            delayUnit = ChronoUnit.SECONDS,
            abortOn = UnauthorizedException.class)
    @ExponentialBackoff
    @BeforeRetry(RetryLogger.class)
    ErrataBuildList getBuilds(@PathParam("id") String erratumId);

    // Get the CDN repositories
    @Traced
    @SpanName("errata.cdn_repos.get")
    @GET
    @Path("/cdn_repos")
    @Retry(
            maxRetries = ERRATA_CLIENT_MAX_RETRIES,
            delay = ERRATA_CLIENT_DELAY,
            delayUnit = ChronoUnit.SECONDS,
            abortOn = UnauthorizedException.class)
    @ExponentialBackoff
    @BeforeRetry(RetryLogger.class)
    ErrataPage<ErrataCDNRepo> getAllCDNRepos(@Valid @BeanParam ErrataQueryParameters pageParameters);

    @ClientExceptionMapper
    @Blocking
    static RuntimeException toException(Response response) {
        String message = response.readEntity(String.class);

        return switch (response.getStatus()) {
            case 400 -> new ClientException("Bad request", List.of(message));
            case 401 ->
                new UnauthorizedException("Caller is unauthorized to access resource; {}", message, List.of(message));
            case 403 -> new ForbiddenException("Caller is forbidden to access resource; {}", message, List.of(message));
            case 404 -> new NotFoundException("Requested resource was not found; {}", message, List.of(message));
            default -> null;
        };

    }

    default Collection<ErrataVariant.VariantData> getVariantOfProductAndProductVersion(
            String productShortName,
            Long productVersionId) {

        Collection<ErrataVariant.VariantData> allVariants = getAllEntities(
                Map.of("filter[product_short_name]", productShortName),
                this::getAllVariants);

        return allVariants.stream()
                .filter(variant -> variant.getAttributes() != null)
                .filter(variant -> variant.getAttributes().getRelationships() != null)
                .filter(variant -> variant.getAttributes().getRelationships().getProductVersion() != null)
                .filter(
                        variant -> productVersionId
                                .equals(variant.getAttributes().getRelationships().getProductVersion().getId()))
                .toList();
    }

    default Map<String, Collection<ErrataCDNRepoNormalized>> getCDNReposOfVariant(
            Set<String> variantNames,
            String shortProductName) {
        Map<String, Collection<ErrataCDNRepoNormalized>> variantToCDNs = new HashMap<>();
        variantNames.forEach(variant -> variantToCDNs.put(variant, getCDNReposOfVariant(variant, shortProductName)));
        return variantToCDNs;
    }

    default Collection<ErrataCDNRepoNormalized> getCDNReposOfVariant(String variantName, String shortProductName) {
        Collection<ErrataCDNRepo> allCDNRepos = getAllEntities(
                Map.of("filter[variant_name]", variantName),
                this::getAllCDNRepos);

        return allCDNRepos.stream()
                .filter(
                        cdn -> cdn.getType().equals("cdn_repos")
                                && !cdn.getAttributes().getContentType().equalsIgnoreCase("docker"))
                .map(cdn -> new ErrataCDNRepoNormalized(cdn, variantName, !"rhel".equalsIgnoreCase(shortProductName)))
                .distinct()
                .toList();
    }

    // Default method for handling pagination logic with a generic type `T` and a function `getPageFunction`
    default <T> Collection<T> getAllEntities(
            Map<String, String> filters,
            Function<ErrataQueryParameters, ErrataPage<T>> getPageFunction) {
        ErrataQueryParameters parameters = ErrataQueryParameters.builder().withFilters(filters).build();

        Collection<T> entities = new ArrayList<>();
        int currentPage;
        int totalPages;

        do {
            ErrataPage<T> response = getPageFunction.apply(parameters);

            if (response.getData() != null && !response.getData().isEmpty()) {
                entities.addAll(response.getData());
            }

            currentPage = response.getPage().getPageNumber() + 1;
            totalPages = response.getPage().getTotalPages();
            parameters.setPageNumber(currentPage);
        } while (currentPage <= totalPages);

        return entities;
    }

}
