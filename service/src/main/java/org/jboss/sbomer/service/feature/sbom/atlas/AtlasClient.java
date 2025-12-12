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
package org.jboss.sbomer.service.feature.sbom.atlas;

import static org.jboss.sbomer.core.rest.faulttolerance.Constants.ATLAS_CLIENT_DELAY;
import static org.jboss.sbomer.core.rest.faulttolerance.Constants.ATLAS_CLIENT_MAX_RETRIES;
import static org.jboss.sbomer.core.rest.faulttolerance.Constants.ATLAS_CLIENT_MAX_DURATION;

import java.time.temporal.ChronoUnit;
import java.util.Map;

import org.eclipse.microprofile.faulttolerance.Retry;
import org.jboss.sbomer.core.rest.faulttolerance.RetryLogger;

import com.fasterxml.jackson.databind.JsonNode;

import io.smallrye.faulttolerance.api.BeforeRetry;
import io.smallrye.faulttolerance.api.ExponentialBackoff;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

/**
 * A client for the Atlas (instance of the Trusted Profile Analyzer).
 */

@Path("/api/v2/sbom")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface AtlasClient {

    @POST
    @Retry(maxRetries = ATLAS_CLIENT_MAX_RETRIES, delay = ATLAS_CLIENT_DELAY, delayUnit = ChronoUnit.SECONDS, maxDuration = ATLAS_CLIENT_MAX_DURATION, durationUnit = ChronoUnit.SECONDS)
    @ExponentialBackoff
    @BeforeRetry(RetryLogger.class)
    void upload(@QueryParam("labels") Map<String, String> labels, JsonNode bom);

}
