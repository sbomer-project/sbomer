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
package org.jboss.sbomer.cli.feature.sbom.client;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import lombok.Data;

/**
 * Represents the content of a remote source JSON file attached to an OSBS container build.
 *
 * @see <a href= "https://github.com/containerbuildsystem/cachito/blob/master/cachito/web/models.py">Cachito Request
 *      model</a>
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class RemoteSource {
    private Integer id;

    private Instant created;

    private String repo;

    private String ref;

    private List<String> pkgManagers;

    private String user;

    private Map<String, String> environmentVariables;

    private List<String> flags;

    private String submittedBy;

    private String state;

    private String stateReason;

    private Instant updated;

    private String configurationFiles;

    private String contentManifest;

    private String environmentVariablesInfo;

    private List<StateHistory> stateHistory;

    private List<Package> packages;

    private List<Dependency> dependencies;

    private Logs logs;

    private String errorOrigin;

    private String errorType;

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class Logs {
        private String url;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class StateHistory {
        private String state;

        private String stateReason;

        private Instant updated;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class Package {
        private String name;

        private String type;

        private String version;

        private List<Dependency> dependencies;

        private String path;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class Dependency {
        private String name;

        private String type;

        private String version;

        private Boolean dev;

        private Dependency replaces;
    }
}
