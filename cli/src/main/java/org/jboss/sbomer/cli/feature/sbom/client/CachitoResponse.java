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

import java.util.Date;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import lombok.Data;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class CachitoResponse {
    private String configurationFiles;

    private String contentManifest;

    private Date created;

    private List<String> dependencies;

    private Map<String, String> environmentVariables;

    private String environmentVariablesInfo;

    private List<String> flags;

    private int id;

    private Logs logs;

    private List<String> packages;

    private List<String> pkgManagers;

    private String ref;

    private String repo;

    private String state;

    private List<StateHistory> stateHistory;

    private String stateReason;

    private String submittedBy;

    private Date updated;

    private String user;

    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class Logs {
        private String url;
    }

    @Data
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public static class StateHistory {
        private String state;

        private String stateReason;

        private Date updated;
    }
}
