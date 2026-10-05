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
import org.spdx.library.ListedLicenses;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaValidatorsConfig;
import com.networknt.schema.SpecVersionDetector;
import com.networknt.schema.resource.MapSchemaMapper;

import lombok.extern.slf4j.Slf4j;

/**
 * A {@link JsonParser} that overrides the SPDX license sub-schema used during CycloneDX BOM validation.
 * <p>
 * Upstream {@code org.cyclonedx.CycloneDxSchema#getJsonSchema} resolves the
 * {@code http://cyclonedx.org/schema/spdx.schema.json} {@code $ref} from the {@code cyclonedx-core-java} jar (an
 * {@code enum} of accepted SPDX license identifiers), which can become stale between library releases. Here we supply
 * that single schema from one generated at runtime (in memory) from {@link ListedLicenses} so that we get a fresh list
 * from the network. Every other schema still comes from the library jar.
 * <p>
 * NOTE: the body of {@link #getJsonSchema(Version, ObjectMapper)} mirrors upstream
 * {@code CycloneDxSchema#getJsonSchema} (cyclonedx-core-java 9.1.0-patch); only the spdx.schema.json mapping differs.
 * Re-check this against upstream on every cyclonedx-core-java bump.
 */
@Slf4j
public class SbomerJsonParser extends JsonParser {
    private static final String CONNECT_TIMEOUT_PROPERTY = "sun.net.client.defaultConnectTimeout";

    private static final String CONNECT_TIMEOUT_MS = "3000";

    /** The {@code spdx.schema.json} content generated once from {@link ListedLicenses}. */
    private static volatile String spdxSchema;

    @Override
    public JsonSchema getJsonSchema(final Version schemaVersion, final ObjectMapper mapper) throws IOException {
        final String spdxSchema;

        try {
            spdxSchema = spdxSchema(mapper);
        } catch (RuntimeException e) {
            log.warn("Falling back to CycloneDX SPDX license list due to error: {}", e.getMessage(), e);
            return super.getJsonSchema(schemaVersion, mapper);
        }

        final InputStream bomSchemaStream = bomSchemaAsStream(schemaVersion);

        final SchemaValidatorsConfig config = new SchemaValidatorsConfig();
        config.setPreloadJsonSchema(false);

        final ClassLoader cl = getClass().getClassLoader();
        final Map<String, String> offlineMappings = new HashMap<>();
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
                // The one mapping that differs from upstream: serve our runtime SPDX license enum from memory
                // instead of the bundled one.
                .schemaLoaders(s -> s.schemas(Map.of("http://cyclonedx.org/schema/spdx.schema.json", spdxSchema)))
                .schemaMappers(s -> s.add(offlineSchemaMapper))
                .build();

        return factory.getSchema(schemaNode, config);
    }

    public static void load() {
        final String previousConnectTimeout = System.setProperty(CONNECT_TIMEOUT_PROPERTY, CONNECT_TIMEOUT_MS);

        try {
            spdxSchema(new ObjectMapper());
        } catch (Exception e) {
            throw new IllegalStateException("Unable to load the SPDX license list for CycloneDX validation", e);
        } finally {
            if (previousConnectTimeout != null) {
                System.setProperty(CONNECT_TIMEOUT_PROPERTY, previousConnectTimeout);
            } else {
                System.clearProperty(CONNECT_TIMEOUT_PROPERTY);
            }
        }

        log.info(
                "Loaded SPDX license list version {} for CycloneDX validation",
                ListedLicenses.getListedLicenses().getLicenseListVersion());
    }

    private static synchronized String spdxSchema(final ObjectMapper mapper) throws IOException {
        if (spdxSchema != null) {
            return spdxSchema;
        }

        final ListedLicenses licenses = ListedLicenses.getListedLicenses();
        final ObjectNode schema = mapper.createObjectNode();
        schema.put("$schema", "http://json-schema.org/draft-07/schema#");
        schema.put("$id", "http://cyclonedx.org/schema/spdx.schema.json");
        schema.put("$comment", licenses.getLicenseListVersion());
        schema.put("type", "string");
        final ArrayNode ids = schema.putArray("enum");
        licenses.getSpdxListedLicenseIds().forEach(ids::add);
        licenses.getSpdxListedExceptionIds().forEach(ids::add);
        spdxSchema = mapper.writeValueAsString(schema);
        return spdxSchema;
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
