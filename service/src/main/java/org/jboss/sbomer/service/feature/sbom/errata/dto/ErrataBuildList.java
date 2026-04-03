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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class ErrataBuildList {

    private Map<String, ProductVersionEntry> productVersions = new LinkedHashMap<>();

    @JsonAnySetter
    public void addProductVersion(String name, ProductVersionEntry productVersionEntry) {
        this.productVersions.put(name, productVersionEntry);
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class ProductVersionEntry {
        private String name;
        private String description;
        private List<Build> builds = new ArrayList<>();
        private SigKey sigKey;
        private SigKey containerSigKey;
        private SigKey defaultSigKey;
        private SigKey imaSigKey;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Build {
        private Map<String, BuildItem> buildItems = new LinkedHashMap<>();

        @JsonAnySetter
        public void addBuildItem(String name, BuildItem buildItem) {
            this.buildItems.put(name, buildItem);
        }
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class BuildItem {
        private String nvr;
        private String nevr;
        private Long id;
        @JsonProperty("is_module")
        private boolean isModule;
        private String addedBy;
        @JsonProperty("is_signed")
        private boolean isSigned;
        private Map<String, VariantArch> variantArch = new LinkedHashMap<>();
        private SigKey sigKey;
    }

    public static class VariantArch extends LinkedHashMap<String, List<BrewFile>> {
    }

    @Data
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class BrewFile {
        private String filename;
        @JsonProperty("is_signed")
        private boolean isSigned;

        @JsonCreator
        public BrewFile(String filename) {
            this.filename = filename;
        }
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class SigKey {
        private String keyid;
        private String name;
    }
}
