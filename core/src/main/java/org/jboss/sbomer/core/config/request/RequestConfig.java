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
package org.jboss.sbomer.core.config.request;

import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.util.Strings;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonProcessingException;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Data
@SuperBuilder(setterPrefix = "with")
@AllArgsConstructor
@NoArgsConstructor
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.EXTERNAL_PROPERTY, property = "type")
@JsonSubTypes({ //
        @JsonSubTypes.Type(ImageRequestConfig.class), //
        @JsonSubTypes.Type(ErrataAdvisoryRequestConfig.class), //
        @JsonSubTypes.Type(PncAnalysisRequestConfig.class), //
        @JsonSubTypes.Type(PncOperationRequestConfig.class), //
        @JsonSubTypes.Type(PncBuildRequestConfig.class), //
})
public abstract class RequestConfig {
    /**
     * The API version of the configuration file. In case of breaking changes, this value will be used to detect the
     * correct (de)serializer.
     */
    @Builder.Default
    String apiVersion = "sbomer.jboss.org/v1alpha1";

    @JsonIgnore
    String type;

    public abstract String getType();

    public String toJson() {
        try {
            return ObjectMapperProvider.json().writerWithDefaultPrettyPrinter().writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new ApplicationException("Cannot serialize configuration into a JSON string", e);
        }
    }

    public static <T extends RequestConfig> T fromString(String value, Class<T> clazz) {
        if (value == null || Strings.isEmpty(value)) {
            return null;
        }

        try {
            return ObjectMapperProvider.json().readValue(value.strip(), clazz);
        } catch (JsonProcessingException e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }
}
