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

import org.eclipse.microprofile.faulttolerance.Retry;
import org.eclipse.microprofile.rest.client.annotation.ClientHeaderParam;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;
import org.jboss.pnc.dto.DeliverableAnalyzerOperation;
import org.jboss.pnc.dto.requests.DeliverablesAnalysisRequest;
import org.jboss.sbomer.core.rest.faulttolerance.RetryLogger;

import io.quarkus.oidc.client.filter.OidcClientFilter;
import io.smallrye.faulttolerance.api.BeforeRetry;
import io.smallrye.faulttolerance.api.ExponentialBackoff;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.jboss.pnc.dto.requests.ScratchDeliverablesAnalysisRequest;

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
    @Retry(maxRetries = PNC_CLIENT_MAX_RETRIES, delay = PNC_CLIENT_DELAY, delayUnit = ChronoUnit.SECONDS)
    @ExponentialBackoff
    @BeforeRetry(RetryLogger.class)
    DeliverableAnalyzerOperation analyzeDeliverables(
            @PathParam("id") String milestoneId,
            DeliverablesAnalysisRequest request);

    @GET
    @Path("/operations/deliverable-analyzer/{id}")
    @Retry(maxRetries = PNC_CLIENT_MAX_RETRIES, delay = PNC_CLIENT_DELAY, delayUnit = ChronoUnit.SECONDS)
    @ExponentialBackoff
    @BeforeRetry(RetryLogger.class)
    DeliverableAnalyzerOperation getDeliverableAnalyzerOperation(@PathParam("id") String operationId);

    @POST
    @Path("/operations/deliverable-analyzer/start")
    DeliverableAnalyzerOperation startScratchDeliverableAnalysis(
            ScratchDeliverablesAnalysisRequest scratchDeliverablesAnalysisRequest);

}
