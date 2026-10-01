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
package org.jboss.sbomer.core.features.sbom.validation;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import org.cyclonedx.Version;
import org.cyclonedx.parsers.JsonParser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaValidatorsConfig;
import com.networknt.schema.SpecVersionDetector;
import com.networknt.schema.resource.MapSchemaMapper;

/**
 * A {@link JsonParser} that overrides the SPDX license sub-schema used during CycloneDX BOM validation.
 * <p>
 * Upstream {@code org.cyclonedx.CycloneDxSchema#getJsonSchema} resolves the
 * {@code http://cyclonedx.org/schema/spdx.schema.json} {@code $ref} from the {@code cyclonedx-core-java} jar (an
 * {@code enum} of accepted SPDX license identifiers). Here we remap that single URI to our own bundled resource
 * ({@value #SPDX_SCHEMA_RESOURCE} in {@code core/src/main/resources}) so we control the set of accepted license
 * identifiers; every other schema still comes from the library jar.
 * <p>
 * NOTE: the body of {@link #getJsonSchema(Version, ObjectMapper)} mirrors upstream
 * {@code CycloneDxSchema#getJsonSchema} (cyclonedx-core-java 9.1.0-patch); only the spdx.schema.json mapping differs.
 * Re-check this against upstream on every cyclonedx-core-java bump.
 */
public class SbomerJsonParser extends JsonParser {

    /** Classpath resource (in {@code core/src/main/resources}) holding our SPDX license enum. */
    static final String SPDX_SCHEMA_RESOURCE = "sbomer-spdx.schema.json";

    @Override
    public JsonSchema getJsonSchema(final Version schemaVersion, final ObjectMapper mapper) throws IOException {
        final InputStream bomSchemaStream = bomSchemaAsStream(schemaVersion);

        final SchemaValidatorsConfig config = new SchemaValidatorsConfig();
        config.setPreloadJsonSchema(false);

        final ClassLoader cl = getClass().getClassLoader();
        final Map<String, String> offlineMappings = new HashMap<>();
        // The one mapping that differs from upstream: our SPDX license enum instead of the bundled one.
        offlineMappings.put(
                "http://cyclonedx.org/schema/spdx.schema.json",
                cl.getResource(SPDX_SCHEMA_RESOURCE).toExternalForm());
        offlineMappings.put(
                "http://cyclonedx.org/schema/jsf-0.82.schema.json",
                cl.getResource("jsf-0.82.schema.json").toExternalForm());
        offlineMappings.put(
                "http://cyclonedx.org/schema/bom-1.2.schema.json",
                cl.getResource("bom-1.2-strict.schema.json").toExternalForm());
        offlineMappings.put(
                "http://cyclonedx.org/schema/bom-1.3.schema.json",
                cl.getResource("bom-1.3-strict.schema.json").toExternalForm());
        offlineMappings.put(
                "http://cyclonedx.org/schema/bom-1.4.schema.json",
                cl.getResource("bom-1.4.schema.json").toExternalForm());
        offlineMappings.put(
                "http://cyclonedx.org/schema/bom-1.5.schema.json",
                cl.getResource("bom-1.5.schema.json").toExternalForm());
        offlineMappings.put(
                "http://cyclonedx.org/schema/bom-1.6.schema.json",
                cl.getResource("bom-1.6.schema.json").toExternalForm());

        final JsonNode schemaNode = mapper.readTree(bomSchemaStream);
        final MapSchemaMapper offlineSchemaMapper = new MapSchemaMapper(offlineMappings);

        final JsonSchemaFactory factory = JsonSchemaFactory
                .builder(JsonSchemaFactory.getInstance(SpecVersionDetector.detect(schemaNode)))
                .jsonMapper(mapper)
                .schemaMappers(s -> s.add(offlineSchemaMapper))
                .build();

        return factory.getSchema(schemaNode, config);
    }

    /**
     * Mirrors the private {@code CycloneDxSchema#getJsonSchemaAsStream}: the top-level BOM schema still comes from the
     * cyclonedx-core-java jar; only the spdx {@code $ref} it contains is remapped above.
     */
    private InputStream bomSchemaAsStream(final Version schemaVersion) {
        final ClassLoader cl = getClass().getClassLoader();

        switch (schemaVersion) {
            case VERSION_12:
                return cl.getResourceAsStream("bom-1.2-strict.schema.json");
            case VERSION_13:
                return cl.getResourceAsStream("bom-1.3-strict.schema.json");
            case VERSION_14:
                return cl.getResourceAsStream("bom-1.4.schema.json");
            case VERSION_15:
                return cl.getResourceAsStream("bom-1.5.schema.json");
            default:
                return cl.getResourceAsStream("bom-1.6.schema.json");
        }
    }
}
