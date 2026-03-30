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
package org.jboss.sbomer.service.feature.sbom.errata.dto;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;
import org.jboss.sbomer.service.feature.sbom.errata.dto.enums.ErrataStatus;
import org.jboss.sbomer.service.feature.sbom.errata.dto.enums.ErrataType;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Data
@Slf4j
@JsonIgnoreProperties(ignoreUnknown = true)
public class Errata {

    @Data
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class WrappedErrata {
        private RHBA rhba;
        private RHEA rhea;
        private RHSA rhsa;
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class RHBA extends Details {
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class RHEA extends Details {
    }

    @Data
    @EqualsAndHashCode(callSuper = true)
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class RHSA extends Details {
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Details {
        private Long id;
        private String fulladvisory;
        private String synopsis;
        private ErrataStatus status;
        private ErrataProduct product;
        @JsonProperty("is_brew")
        private Boolean brew;
        @JsonProperty("group_id")
        private Long groupId;
        @JsonProperty("old_advisory")
        private String oldAdvisory;
        @JsonProperty("text_only")
        private Boolean textonly;
        @JsonProperty("content_types")
        private List<String> contentTypes = new ArrayList<>();

        public boolean hasKnownContentType() {
            for (String type : contentTypes) {
                if (type == null) {
                    continue;
                }

                switch (type) {
                    case "docker", "rpm", "module":
                        return true;
                    default:
                        break;
                }
            }

            return false;
        }

        @JsonProperty("created_at")
        private Instant createdAt;
        @JsonProperty("actual_ship_date")
        private Instant actualShipDate;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ErrataProduct {
        private Long id;
        private String name;
        @JsonProperty("short_name")
        private String shortName;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class WrappedContent {
        private Content content;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Content {
        @JsonProperty("id")
        private Long id;
        @JsonProperty("errata_id")
        private Long errataId;
        private String topic;
        private String description;
        private String solution;
        private String cve;
        @JsonProperty("how_to_test")
        private String notes;
        @JsonProperty("updated_at")
        private Instant updatedAt;
        @JsonProperty("text_only_cpe")
        private String textOnlyCpe;
        @JsonProperty("product_version_text")
        private String productVersionText;
    }

    private WrappedErrata errata;

    @JsonProperty("original_type")
    private ErrataType originalType;

    private WrappedContent content;

    public Optional<Details> getDetails() {
        return switch (originalType) {
            case RHSA -> Optional.of(errata.rhsa);
            case RHBA -> Optional.of(errata.rhba);
            case RHEA -> Optional.of(errata.rhea);
        };
    }

    public Optional<JsonNode> getNotesMapping() {

        // Check if the string is null or empty
        if (content.content.notes == null || content.content.notes.trim().isEmpty()) {
            return Optional.empty();
        }

        try {
            // Try to parse the string into a JsonNode
            return Optional.of(ObjectMapperProvider.json().readTree(content.content.notes));
        } catch (Exception e) {
            log.info("The erratum does not contain a notes content with JSON text: {}", e.getMessage());
            return Optional.empty();
        }
    }
}
