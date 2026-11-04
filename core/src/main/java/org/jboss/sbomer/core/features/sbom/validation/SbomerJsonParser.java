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

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.cyclonedx.Version;
import org.cyclonedx.parsers.JsonParser;
import org.spdx.library.ListedLicenses;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SchemaRegistryConfig;
import com.networknt.schema.dialect.DefaultDialectRegistry;
import com.networknt.schema.dialect.Dialect;
import com.networknt.schema.dialect.DialectRegistry;
import com.networknt.schema.dialect.Draft7;
import com.networknt.schema.keyword.NonValidationKeyword;
import com.networknt.schema.serialization.DefaultNodeReader;

import lombok.extern.slf4j.Slf4j;

/**
 * A {@link JsonParser} that overrides the SPDX license sub-schema used during CycloneDX BOM validation.
 * <p>
 * Upstream {@code org.cyclonedx.CycloneDxSchema#getJsonSchema} resolves the
 * {@code http://cyclonedx.org/schema/spdx.schema.json} {@code $ref} from the {@code cyclonedx-core-java} jar (an
 * {@code enum} of accepted SPDX license identifiers), which can become stale between library releases. Here we supply
 * that single schema from one generated at runtime (in memory): the union of the {@link ListedLicenses} list (fetched
 * from the network, falling back to the list bundled in {@code java-spdx-library}) and the list bundled in the
 * {@code cyclonedx-core-java} jar, so that we validate against whichever is newer. Every other schema still comes from
 * the library jar.
 * <p>
 * NOTE: the body of {@link #getJsonSchema(Version, ObjectMapper)} mirrors upstream
 * {@code CycloneDxSchema#getJsonSchema} (cyclonedx-core-java 13.4.0); only the spdx.schema.json mapping differs.
 * Re-check this against upstream on every cyclonedx-core-java bump.
 */
@Slf4j
public class SbomerJsonParser extends JsonParser {
    private static final String CONNECT_TIMEOUT_PROPERTY = "sun.net.client.defaultConnectTimeout";

    private static final String CONNECT_TIMEOUT_MS = "3000";

    private static final String SPDX_SCHEMA_IRI = "http://cyclonedx.org/schema/spdx.schema.json";

    private static final String SPDX_SCHEMA_RESOURCE = "spdx.schema.json";

    /** The {@code spdx.schema.json} content generated once from {@link ListedLicenses} and the bundled list. */
    private static volatile String spdxSchema;

    @Override
    public com.networknt.schema.Schema getJsonSchema(Version schemaVersion, final ObjectMapper mapper)
            throws IOException {
        final String spdxSchema;

        try {
            spdxSchema = spdxSchema(mapper);
        } catch (RuntimeException e) {
            log.warn("Falling back to CycloneDX SPDX license list due to error: {}", e.getMessage(), e);
            return super.getJsonSchema(schemaVersion, mapper);
        }

        final InputStream spdxInstream = getJsonSchemaAsStream(schemaVersion);
        final SchemaRegistryConfig config = SchemaRegistryConfig.builder().preloadSchema(false).build();

        final Map<String, String> offlineMappings = new HashMap<>();
        offlineMappings.put("http://cyclonedx.org/schema/jsf-0.82.schema.json", "jsf-0.82.schema.json");
        offlineMappings.put("http://cyclonedx.org/schema/bom-1.2.schema.json", "bom-1.2-strict.schema.json");
        offlineMappings.put("http://cyclonedx.org/schema/bom-1.3.schema.json", "bom-1.3-strict.schema.json");
        offlineMappings.put("http://cyclonedx.org/schema/bom-1.4.schema.json", "bom-1.4.schema.json");
        offlineMappings.put("http://cyclonedx.org/schema/bom-1.5.schema.json", "bom-1.5.schema.json");
        offlineMappings.put("http://cyclonedx.org/schema/bom-1.6.schema.json", "bom-1.6.schema.json");
        offlineMappings.put("http://cyclonedx.org/schema/bom-1.7.schema.json", "bom-1.7.schema.json");
        offlineMappings
                .put("http://cyclonedx.org/schema/cryptography-defs.schema.json", "cryptography-defs.schema.json");

        JsonNode schemaNode = mapper.readTree(spdxInstream);
        final DialectRegistry dialectRegistry = new DefaultDialectRegistry(getCycloneDxJsonDialect());

        final ClassLoader classLoader = this.getClass().getClassLoader();
        final SchemaRegistry registry = SchemaRegistry.builder()
                .nodeReader(DefaultNodeReader.builder().jsonMapper(mapper).build())
                // Load schemas from classpath resources using the classloader that owns
                // *this* class. json-schema-validator otherwise uses the current thread's
                // context classloader, which may not be able to access the schema resources.
                // https://github.com/CycloneDX/cyclonedx-core-java/issues/849
                .resourceLoaders(b -> b.add(iri -> {
                    // The one mapping that differs from upstream: serve our runtime SPDX license enum from memory
                    // instead of the bundled one.
                    if (SPDX_SCHEMA_IRI.equals(iri.toString())) {
                        return () -> new ByteArrayInputStream(spdxSchema.getBytes(StandardCharsets.UTF_8));
                    }

                    final String resource = offlineMappings.get(iri.toString());
                    if (resource == null) {
                        return null;
                    }

                    return () -> {
                        final InputStream in = classLoader.getResourceAsStream(resource);
                        if (in == null) {
                            throw new FileNotFoundException(resource);
                        }

                        return in;
                    };
                }))
                .schemaRegistryConfig(config)
                .dialectRegistry(dialectRegistry)
                .build();
        return registry.getSchema(schemaNode);
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
        final JsonNode bundledSchema = bundledSpdxSchema(mapper);
        final Set<String> ids = new LinkedHashSet<>(licenses.getSpdxListedLicenseIds());
        ids.addAll(licenses.getSpdxListedExceptionIds());
        bundledSchema.get("enum").forEach(id -> ids.add(id.asText()));

        final ObjectNode schema = mapper.createObjectNode();
        schema.put("$schema", "http://json-schema.org/draft-07/schema#");
        schema.put("$id", SPDX_SCHEMA_IRI);
        schema.put("$comment", licenses.getLicenseListVersion() + " + " + bundledSchema.path("$comment").asText());
        schema.put("type", "string");
        final ArrayNode enumNode = schema.putArray("enum");
        ids.forEach(enumNode::add);
        spdxSchema = mapper.writeValueAsString(schema);
        return spdxSchema;
    }

    private static JsonNode bundledSpdxSchema(final ObjectMapper mapper) throws IOException {
        try (InputStream in = SbomerJsonParser.class.getClassLoader().getResourceAsStream(SPDX_SCHEMA_RESOURCE)) {
            if (in == null) {
                throw new FileNotFoundException(SPDX_SCHEMA_RESOURCE);
            }

            return mapper.readTree(in);
        }
    }

    static Dialect getCycloneDxJsonDialect() {
        return Dialect.builder(Draft7.getInstance())
                .keyword(new NonValidationKeyword("meta:enum"))
                .keyword(new NonValidationKeyword("deprecated"))
                .build();
    }

    /**
     * Mirrors the private {@code CycloneDxSchema#getJsonSchemaAsStream}: the top-level BOM schema still comes from the
     * cyclonedx-core-java jar; only the spdx {@code $ref} it contains is remapped above.
     */
    private InputStream getJsonSchemaAsStream(final Version schemaVersion) {
        if (Version.VERSION_12 == schemaVersion) {
            return this.getClass().getClassLoader().getResourceAsStream("bom-1.2-strict.schema.json");
        } else if (Version.VERSION_13 == schemaVersion) {
            return this.getClass().getClassLoader().getResourceAsStream("bom-1.3-strict.schema.json");
        } else if (Version.VERSION_14 == schemaVersion) {
            return this.getClass().getClassLoader().getResourceAsStream("bom-1.4.schema.json");
        } else if (Version.VERSION_15 == schemaVersion) {
            return this.getClass().getClassLoader().getResourceAsStream("bom-1.5.schema.json");
        } else if (Version.VERSION_16 == schemaVersion) {
            return this.getClass().getClassLoader().getResourceAsStream("bom-1.6.schema.json");
        } else {
            return this.getClass().getClassLoader().getResourceAsStream("bom-1.7.schema.json");
        }
    }
}
