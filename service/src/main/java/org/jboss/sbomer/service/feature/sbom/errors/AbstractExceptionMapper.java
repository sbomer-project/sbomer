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
package org.jboss.sbomer.service.feature.sbom.errors;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.jboss.sbomer.core.errors.ErrorResponse;
import org.slf4j.helpers.MessageFormatter;

import jakarta.inject.Inject;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Request;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.ResponseBuilder;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.ExceptionMapper;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class AbstractExceptionMapper<T extends Throwable> implements ExceptionMapper<T> {
    @Inject
    UriInfo uriInfo;

    @Inject
    Request request;

    @Inject
    SecurityContext securityContext;

    @Inject
    HttpHeaders httpHeaders;

    String generateErrorId() {
        return UUID.randomUUID().toString();
    }

    Status getStatus(T ex) { // NOSONAR: This is an abstract class, the implementation may use ex
        return Status.INTERNAL_SERVER_ERROR;
    }

    String errorMessage(T ex) { // NOSONAR: This is an abstract class, the implementation may use ex
        return "An error occurred while processing your request, please contact administrator providing the 'errorId'";
    }

    /**
     * <p>
     * Override to provide any additional error messages that can be useful for the client to understand the problem.
     * See {@link ErrorResponse#getErrors()}.
     * </p>
     *
     * <p>
     * By default, an empty list is returned.
     * </p>
     *
     * @return the list of custom error messages
     */
    List<String> customErrors(T ex) {
        return new ArrayList<>();
    }

    /**
     * <p>
     * A hook that is executed before the response is returned. It can be used, for example, to help audit things (log
     * messages).
     * </p>
     *
     * <p>
     * Returned {@link Response} object is returned to the client.
     * </p>
     *
     * @param responseBuilder The prepared default {@link Response} object.
     * @param ex The {@link Throwable} containing the cause
     */
    Response hook(ResponseBuilder responseBuilder, T ex) {
        return responseBuilder.build();
    }

    ErrorResponse errorResponse(T ex) {
        return ErrorResponse.builder()
                .resource(uriInfo.getPath())
                .errorId(generateErrorId())
                .error(getStatus(ex).getReasonPhrase())
                .errors(customErrors(ex))
                .message(errorMessage(ex))
                .build();
    }

    void copyHeaders(T ex, ResponseBuilder builder) {
        Response response = null;

        if (ex instanceof WebApplicationException waex) {
            response = waex.getResponse();
        }

        if (response == null) {
            return;
        }

        for (Map.Entry<String, List<Object>> en : response.getHeaders().entrySet()) {
            String headerName = en.getKey();
            List<Object> headerValues = en.getValue();
            for (Object headerValue : headerValues) {
                builder.header(headerName, headerValue);
            }
        }
    }

    static boolean isServerError(int statusCode) {
        return statusCode >= 500;
    }

    @Override
    public Response toResponse(T ex) {
        // Prepare default error entity for a given exception
        ErrorResponse errorResponse = errorResponse(ex);

        if (isServerError(getStatus(ex).getStatusCode())) {
            log.error("ErrorId: '{}'", errorResponse.getErrorId());
        } else {
            log.warn("ErrorId: '{}'", errorResponse.getErrorId());
        }

        // Prepare initial response builder with default 500 error and JSON content type
        ResponseBuilder responseBuilder = Response.status(getStatus(ex))
                .entity(errorResponse)
                .type(MediaType.APPLICATION_JSON);

        // If headers are available, copy them
        copyHeaders(ex, responseBuilder);

        // Customize the response, if needed
        Response response = hook(responseBuilder, ex);

        // Log the entity in any case
        log.debug(response.getEntity().toString());

        return response;
    }

    String formattedString(String message, Object... params) {
        return MessageFormatter.arrayFormat(message, params).getMessage();
    }
}
