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

import com.fasterxml.jackson.databind.exc.MismatchedInputException;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.ResponseBuilder;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.ext.Provider;
import lombok.extern.slf4j.Slf4j;

/**
 * Handles cases where the received content cannot be deserialized.
 */
@Provider
@Slf4j
public class MismatchedInputExceptionMapper extends AbstractExceptionMapper<MismatchedInputException> {

    @Override
    Status getStatus(MismatchedInputException ex) {
        return Status.BAD_REQUEST;
    }

    @Override
    Response hook(ResponseBuilder responseBuilder, MismatchedInputException ex) {
        log.warn("Received content that cannot be deserialized", ex);
        return responseBuilder.build();
    }

    @Override
    String errorMessage(MismatchedInputException ex) {
        return formattedString("An error occurred while deserializing provided content, please check your body 🤼");
    }
}
