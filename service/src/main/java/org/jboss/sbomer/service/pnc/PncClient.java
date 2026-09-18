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
package org.jboss.sbomer.service.pnc;

import static org.jboss.sbomer.core.rest.faulttolerance.Constants.PNC_CLIENT_DELAY;
import static org.jboss.sbomer.core.rest.faulttolerance.Constants.PNC_CLIENT_MAX_RETRIES;

import java.time.temporal.ChronoUnit;
import java.util.List;

import org.eclipse.microprofile.faulttolerance.Retry;
import org.eclipse.microprofile.rest.client.annotation.ClientHeaderParam;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;
import org.jboss.pnc.dto.DeliverableAnalyzerOperation;
import org.jboss.pnc.dto.requests.DeliverablesAnalysisRequest;
import org.jboss.sbomer.core.errors.ClientException;
import org.jboss.sbomer.core.errors.ForbiddenException;
import org.jboss.sbomer.core.errors.NotFoundException;
import org.jboss.sbomer.core.errors.UnauthorizedException;
import org.jboss.sbomer.core.rest.faulttolerance.RetryLogger;

import io.quarkus.oidc.client.filter.OidcClientFilter;
import io.quarkus.rest.client.reactive.ClientExceptionMapper;
import io.smallrye.faulttolerance.api.BeforeRetry;
import io.smallrye.faulttolerance.api.ExponentialBackoff;
import io.smallrye.reactive.messaging.annotations.Blocking;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@ApplicationScoped
@ClientHeaderParam(name = "User-Agent", value = "SBOMer")
@RegisterRestClient(configKey = "pnc")
@Path("/pnc-rest/v2")
@OidcClientFilter
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface PncClient {
    @POST
    @Path("/product-milestones/{id}/analyze-deliverables")
    @Retry(
            maxRetries = PNC_CLIENT_MAX_RETRIES,
            delay = PNC_CLIENT_DELAY,
            delayUnit = ChronoUnit.SECONDS,
            abortOn = ClientException.class)
    @ExponentialBackoff
    @BeforeRetry(RetryLogger.class)
    DeliverableAnalyzerOperation analyzeDeliverables(
            @PathParam("id") String milestoneId,
            DeliverablesAnalysisRequest request);

    @GET
    @Path("/operations/deliverable-analyzer/{id}")
    @Retry(
            maxRetries = PNC_CLIENT_MAX_RETRIES,
            delay = PNC_CLIENT_DELAY,
            delayUnit = ChronoUnit.SECONDS,
            abortOn = ClientException.class)
    @ExponentialBackoff
    @BeforeRetry(RetryLogger.class)
    DeliverableAnalyzerOperation getDeliverableAnalyzerOperation(@PathParam("id") String operationId);

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
}
