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
package org.jboss.sbomer.service.rest.api.v1beta1;

import static org.jboss.sbomer.service.feature.sbom.UserRoles.USER_DELETE_ROLE;

import java.util.List;

import org.eclipse.microprofile.context.ManagedExecutor;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.ExampleObject;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.parameters.RequestBody;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.sbomer.core.SchemaValidator.ValidationResult;
import org.jboss.sbomer.core.config.RequestConfigSchemaValidator;
import org.jboss.sbomer.core.config.request.ErrataAdvisoryRequestConfig;
import org.jboss.sbomer.core.config.request.ImageRequestConfig;
import org.jboss.sbomer.core.config.request.PncAnalysisRequestConfig;
import org.jboss.sbomer.core.config.request.PncBuildRequestConfig;
import org.jboss.sbomer.core.config.request.PncOperationRequestConfig;
import org.jboss.sbomer.core.config.request.RequestConfig;
import org.jboss.sbomer.core.dto.v1beta1.V1Beta1GenerationRecord;
import org.jboss.sbomer.core.dto.v1beta1.V1Beta1RequestRecord;
import org.jboss.sbomer.core.errors.ClientException;
import org.jboss.sbomer.core.errors.ErrorResponse;
import org.jboss.sbomer.core.errors.NotFoundException;
import org.jboss.sbomer.core.errors.ServiceUnavailableException;
import org.jboss.sbomer.core.features.sbom.config.DeliverableAnalysisConfig;
import org.jboss.sbomer.core.features.sbom.config.OperationConfig;
import org.jboss.sbomer.core.features.sbom.config.PncBuildConfig;
import org.jboss.sbomer.core.features.sbom.config.SyftImageConfig;
import org.jboss.sbomer.core.features.sbom.rest.Page;
import org.jboss.sbomer.core.features.sbom.utils.MDCUtils;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.sbomer.core.utils.PaginationParameters;
import org.jboss.sbomer.service.feature.FeatureFlags;
import org.jboss.sbomer.service.feature.s3.S3StorageHandler;
import org.jboss.sbomer.service.feature.sbom.model.RequestEvent;
import org.jboss.sbomer.service.feature.sbom.model.SbomGenerationRequest;
import org.jboss.sbomer.service.feature.sbom.service.AdvisoryService;
import org.jboss.sbomer.service.feature.sbom.service.SbomService;
import org.jboss.sbomer.service.rest.RestUtils;
import org.jboss.sbomer.service.rest.mapper.V1Beta1Mapper;

import com.fasterxml.jackson.jakarta.rs.yaml.YAMLMediaTypes;

import io.opentelemetry.api.trace.Span;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.BeanParam;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;

@Path("/api/v1beta1/generations")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@ApplicationScoped
@PermitAll
@Tag(name = "v1beta1")
@Slf4j
public class GenerationsV1Beta1 {
    @Inject
    V1Beta1Mapper mapper;

    @Inject
    SbomService sbomService;

    @Inject
    AdvisoryService advisoryService;

    @Inject
    RequestConfigSchemaValidator requestConfigSchemaValidator;

    @Inject
    FeatureFlags featureFlags;

    @Inject
    S3StorageHandler s3StorageHandler;

    @Inject
    ManagedExecutor executor;

    @POST
    @Consumes({ MediaType.APPLICATION_JSON, YAMLMediaTypes.APPLICATION_JACKSON_YAML })
    @Operation(
            summary = "Request manifest generation for a supported content",
            description = "Schedules generation of a manifest. This is an asynchronous call. It does perform the generation behind the scenes.")
    @RequestBody(
            content = @Content(
                    schema = @Schema(
                            required = true,
                            discriminatorProperty = "type",
                            anyOf = { PncBuildConfig.class, SyftImageConfig.class }),
                    examples = { //
                            @ExampleObject(
                                    name = "PNC build with defaults",
                                    description = "Requests manifest generation for a PNC build with identifier: ARYT3LBXDVYAC using defaults",
                                    value = "{\"type\": \"pnc-build\", \"buildId\": \"ARYT3LBXDVYAC\"}"),
                            @ExampleObject(
                                    name = "PNC build with one product defined and a custom generator",
                                    description = "Requests manifest generation for a PNC build with identifier: ARYT3LBXDVYAC with custom generator parameters",
                                    value = "{\"type\": \"pnc-build\", \"buildId\": \"ARYT3LBXDVYAC\", \"products\":[{\"generator\":{\"type\":\"maven-domino\",\"args\":\"--warn-on-missing-scm --legacy-scm-locator --hashes=false\",\"version\":\"0.0.127\"}}]}"),
                            @ExampleObject(
                                    name = "PNC operation",
                                    description = "Requests manifest generation for a PNC operation with identifier: A5WL3DFZ3AIAA",
                                    value = "{\"type\": \"pnc-operation\", \"operationId\": \"A5WL3DFZ3AIAA\"}"),
                            @ExampleObject(
                                    name = "PNC analysis",
                                    description = "Request manifest generation for following zips, storing the results under PNC milestone ID 1234",
                                    value = "{\"type\": \"pnc-analysis\", \"milestoneId\": \"1234\", \"urls\": [\"https://download.host.com/staging/product-a/release-b/first.zip\", \"https://download.host.com/staging/product-a/release-b/second.zip\"]}"),
                            @ExampleObject(
                                    name = "Errata Tool advisory",
                                    description = "Requests manifest generation for the 12345 advisory. Can also take an optional forceBuild boolean field (defaults to false) to force build manifests to be generated for the advisory.",
                                    value = "{\"type\": \"errata-advisory\", \"advisoryId\": 12345}"),
                            @ExampleObject(
                                    name = "Container image",
                                    description = "Requests manifest generation for a container image with iodentifier: registry.access.redhat.com/ubi9/ubi-micro:9.4",
                                    value = "{\"type\": \"image\", \"image\": \"registry.access.redhat.com/ubi9/ubi-micro:9.4\"}") //
                    }))
    @APIResponse(
            responseCode = "202",
            description = "Manifest generation successfully requested",
            content = @Content(schema = @Schema(implementation = V1Beta1RequestRecord.class)))
    @APIResponse(
            responseCode = "400",
            description = "Failed while processing the request, please verify the provided config.",
            content = @Content(
                    mediaType = MediaType.APPLICATION_JSON,
                    schema = @Schema(implementation = ErrorResponse.class)))
    @APIResponse(
            responseCode = "500",
            description = "Internal server error",
            content = @Content(mediaType = MediaType.APPLICATION_JSON))
    public Response createFromConfig(RequestConfig config, @Context ContainerRequestContext requestContext)
            throws Exception {
        if (config == null) {
            throw new ClientException("No config provided");
        }

        log.info("Validating config: {}", ObjectMapperProvider.json().writeValueAsString(config));
        ValidationResult validationResult = requestConfigSchemaValidator.validate(config);

        if (!validationResult.isValid()) {
            throw new ClientException("Invalid config", validationResult.getErrors());
        }

        log.info("Provided config is valid! Scheduling for generation.");

        RequestEvent request = RestUtils.createRequestFromRestEvent(config, requestContext, Span.current());

        Runnable asyncTask;

        if (config instanceof ErrataAdvisoryRequestConfig) {
            asyncTask = () -> {
                try {
                    log.info("Starting asynchronous for Errata generation request: {}", request.getId());
                    advisoryService.generateFromAdvisory(request);
                    log.info("Completed asynchronous for Errata generation request: {}", request.getId());
                } catch (Exception e) {
                    log.error("Failed to generate Errata advisory asynchronously for request: {}", request.getId(), e);
                }
            };
        } else if (config instanceof PncBuildRequestConfig) {
            asyncTask = () -> {
                try {
                    log.info("Starting asynchronous PNC build generation for generation request: {}", request.getId());
                    sbomService.generateFromBuild(request, config, null);
                    log.info("Completed asynchronous PNC build generation for generation request: {}", request.getId());
                } catch (Exception e) {
                    log.error(
                            "Failed to generate PNC build asynchronously for generation request: {}",
                            request.getId(),
                            e);
                }
            };
        } else if (config instanceof PncAnalysisRequestConfig analysisConfig) {
            asyncTask = () -> {
                try {
                    log.info("Starting asynchronous PNC analysis for generation request: {}", request.getId());
                    sbomService.generateNewOperation(
                            request,
                            DeliverableAnalysisConfig.builder()
                                    .withDeliverableUrls(analysisConfig.getUrls())
                                    .withMilestoneId(analysisConfig.getMilestoneId())
                                    .build());
                    log.info("Completed asynchronous PNC analysis for generation request:  {}", request.getId());
                } catch (Exception e) {
                    log.error(
                            "Failed to generate PNC analysis asynchronously for generation request: {}",
                            request.getId(),
                            e);
                }
            };
        } else if (config instanceof ImageRequestConfig imageConfig) {
            asyncTask = () -> {
                try {
                    log.info("Starting asynchronous container image for generation request: {}", request.getId());
                    sbomService.generateSyftImage(
                            request,
                            SyftImageConfig.builder().withImage(imageConfig.getImage()).build());
                    log.info("Completed asynchronous container image for generation request: {}", request.getId());
                } catch (Exception e) {
                    log.error(
                            "Failed to generate container image asynchronously for generation request: {}",
                            request.getId(),
                            e);
                }
            };
        } else if (config instanceof PncOperationRequestConfig operationConfig) {
            asyncTask = () -> {
                try {
                    log.info("Starting asynchronous PNC operation for generation request: {}", request.getId());
                    sbomService.generateFromOperation(
                            request,
                            OperationConfig.builder().withOperationId(operationConfig.getOperationId()).build());
                    log.info("Completed asynchronous PNC operation for generation request: {}", request.getId());
                } catch (Exception e) {
                    log.error(
                            "Failed to generate PNC operation asynchronously for generation request: {}",
                            request.getId(),
                            e);
                }
            };
        } else {
            // This case should ideally not be hit if validation is exhaustive
            log.error("Unknown config type received: {}", config.getClass().getName());
            throw new ClientException("Unsupported config type: " + config.getClass().getName());
        }

        executor.submit(asyncTask);

        /*
         * We don't want to hang around waiting for generations to start, this was mainly an issue for big Erratum with
         * lots of builds.
         *
         * The request handle can be used by the client to track the gneration progress
         */
        return Response.accepted(mapper.toRecord(request)).build();
    }

    @GET
    @Path("/{id}")
    @Operation(
            summary = "Get specific manifest generation request",
            description = "Get generation request for the provided identifier or purl")
    @Parameter(
            name = "id",
            description = "Manifest generation request identifier",
            examples = { @ExampleObject(value = "88CA2291D4014C6", name = "Generation request identifier") })
    @APIResponse(
            responseCode = "200",
            description = "The generation request",
            content = @Content(
                    mediaType = MediaType.APPLICATION_JSON,
                    schema = @Schema(implementation = V1Beta1GenerationRecord.class)))
    @APIResponse(
            responseCode = "400",
            description = "Malformed request",
            content = @Content(
                    mediaType = MediaType.APPLICATION_JSON,
                    schema = @Schema(implementation = ErrorResponse.class)))
    @APIResponse(
            responseCode = "404",
            description = "Generation request could not be found",
            content = @Content(
                    mediaType = MediaType.APPLICATION_JSON,
                    schema = @Schema(implementation = ErrorResponse.class)))
    @APIResponse(
            responseCode = "500",
            description = "Internal server error",
            content = @Content(
                    mediaType = MediaType.APPLICATION_JSON,
                    schema = @Schema(implementation = ErrorResponse.class)))
    public V1Beta1GenerationRecord getGenerationRequestById(@PathParam("id") String generationRequestId) {
        SbomGenerationRequest generationRequest = SbomGenerationRequest.findById(generationRequestId); // NOSONAR

        if (generationRequest == null) {
            throw new NotFoundException("Generation request with id '{}' could not be found", generationRequestId);
        }

        return mapper.toRecord(generationRequest);
    }

    @GET
    @Operation(
            summary = "Search manifest generation requests",
            description = "Paginated list of generation requests using RSQL advanced search.")
    @Parameter(
            name = "query",
            description = "A RSQL query to search the generation requests",
            examples = { @ExampleObject(
                    name = "Find all generation requests with provided identifier",
                    value = "identifier=eq=ABCDEFGHIJKLM") })
    @Parameter(
            name = "sort",
            description = "Optional RSQL sort",
            examples = { @ExampleObject(name = "Order generation requests by id in ascending order", value = "id=asc="),
                    @ExampleObject(
                            name = "Order generation requests by creation time in descending order",
                            value = "creationTime=desc=") })
    @APIResponse(
            responseCode = "200",
            description = "Paginated list of generation requests in the system for a specified RSQL query.",
            content = @Content(mediaType = MediaType.APPLICATION_JSON))
    @APIResponse(
            responseCode = "400",
            description = "Failed while parsing the provided RSQL string, please verify the correct syntax.",
            content = @Content(mediaType = MediaType.APPLICATION_JSON))
    @APIResponse(
            responseCode = "500",
            description = "Internal server error",
            content = @Content(mediaType = MediaType.APPLICATION_JSON))
    public Page<V1Beta1GenerationRecord> searchGenerationRequests(
            @Valid @BeanParam PaginationParameters paginationParams,
            @QueryParam("query") String rsqlQuery,
            @DefaultValue("creationTime=desc=") @QueryParam("sort") String sort) {
        Page<SbomGenerationRequest> requests = sbomService.searchSbomRequestsByQueryPaginated(
                paginationParams.getPageIndex(),
                paginationParams.getPageSize(),
                rsqlQuery,
                sort);

        return mapper.generationsToRecordPage(requests);
    }

    @DELETE
    @Consumes(MediaType.WILDCARD)
    @Path("/{id}")
    @RolesAllowed(USER_DELETE_ROLE)
    @Operation(
            summary = "Delete generation request specified by id",
            description = "Delete the specified generation request from the database")
    @Parameter(name = "id", description = "The generation request identifier")
    @APIResponse(responseCode = "200", description = "Generation request was successfully deleted")
    @APIResponse(responseCode = "404", description = "Specified SBOM generation request could not be found")
    @APIResponse(responseCode = "500", description = "Internal server error")
    public Response deleteGenerationRequest(@PathParam("id") final String id) {

        try {
            MDCUtils.addIdentifierContext(id);
            sbomService.deleteSbomRequest(id);

            return Response.ok().build();
        } finally {
            MDCUtils.removeIdentifierContext();
        }
    }

    @GET
    @Consumes({ MediaType.APPLICATION_JSON, YAMLMediaTypes.APPLICATION_JACKSON_YAML })
    @Operation(summary = "List all log files available for generation request")
    @Path("/{id}/logs")
    @APIResponse(responseCode = "200", description = "List all log files available for generation request")
    @APIResponse(
            responseCode = "404",
            description = "Given generation request could not be found",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    @APIResponse(
            responseCode = "500",
            description = "Internal server error",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    @APIResponse(
            responseCode = "503",
            description = "Content cannot be returned at this time",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    public Response getLog(@PathParam("id") String generationRequestId) {
        if (!featureFlags.s3Storage()) {
            throw new ServiceUnavailableException("S3 feature is disabled currently, try again later");
        }

        log.info("Fetching list of paths to log files for GenerationRequest '{}'", generationRequestId);

        List<String> paths = s3StorageHandler.listLogFilesInBucket(generationRequestId);

        return Response.ok(paths).build();
    }

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes({ MediaType.APPLICATION_JSON, YAMLMediaTypes.APPLICATION_JACKSON_YAML })
    @Operation(summary = "Fetch generation log file content on a specified path")
    @Path("/{id}/logs/{path}")
    @APIResponse(
            responseCode = "200",
            description = "Log file content",
            content = @Content(mediaType = MediaType.TEXT_PLAIN))
    @APIResponse(
            responseCode = "500",
            description = "Internal server error",
            content = @Content(mediaType = MediaType.APPLICATION_JSON))
    public Response getLog(@PathParam("id") String generationRequestId, @PathParam("path") String path) {
        if (!featureFlags.s3Storage()) {
            throw new ServiceUnavailableException("S3 feature is disabled currently, try again later");
        }

        log.info("Fetching log for GenerationRequest '{}' on path '{}'", generationRequestId, path);

        String log = s3StorageHandler.getLog(generationRequestId, path);

        return Response.ok(log).build();
    }
}
