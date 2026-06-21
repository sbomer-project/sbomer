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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.jboss.sbomer.core.features.sbom.utils.CustomInstantDeserializer;
import org.jboss.sbomer.service.feature.sbom.features.umb.consumer.model.ErrataStatusChangeMessageBody;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

public class ErrataMessageHelper {
    private ErrataMessageHelper() {
        throw new IllegalStateException("This is a utility class that should not be instantiated");
    }

    private static final ObjectMapper JSON_OBJECT_MAPPER = new ObjectMapper().registerModule(new JavaTimeModule())
            .registerModule(new SimpleModule().addDeserializer(Instant.class, new CustomInstantDeserializer()))
            .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
            .setPropertyNamingStrategy(PropertyNamingStrategies.LOWER_CAMEL_CASE)
            .setSerializationInclusion(Include.NON_NULL)
            .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.READ_UNKNOWN_ENUM_VALUES_AS_NULL)
            .disable(SerializationFeature.FAIL_ON_UNWRAPPED_TYPE_IDENTIFIERS);

    public static String decode(byte[] encodedJson) {
        return new String(encodedJson, StandardCharsets.US_ASCII);
    }

    public static ErrataStatusChangeMessageBody fromStatusChangeMessage(String json) throws JsonProcessingException {
        return JSON_OBJECT_MAPPER.readValue(json, ErrataStatusChangeMessageBody.class);
    }

    public static ErrataStatusChangeMessageBody fromStatusChangeMessage(JsonNode jsonNode) throws IOException {
        return JSON_OBJECT_MAPPER.readValue(
                jsonNode.isTextual() ? jsonNode.textValue().getBytes() : jsonNode.toString().getBytes(),
                ErrataStatusChangeMessageBody.class);
    }

}
