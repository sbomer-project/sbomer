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
package org.jboss.sbomer.core.features.sbom.config;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonTypeName;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import lombok.extern.jackson.Jacksonized;

@Data
@SuperBuilder(setterPrefix = "with")
@Jacksonized
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonTypeName("brew-rpm")
public class BrewRPMConfig extends Config {

    /**
     * Advisory id in Errata.
     */
    Long advisoryId;

    /**
     * Advisory full-name in Errata.
     */
    String advisory;

    /**
     * Product version id in Errata.
     */
    Long productVersionId;

    /**
     * Product version name in Errata.
     */
    String productVersion;

    /**
     * Brew build id attached to the advisory.
     */
    Long brewBuildId;

    /**
     * Brew build NVR attached to the advisory.
     */
    String brewBuildNVR;

    /**
     * Enable CBOM (Cryptographic Bill of Materials) generation.
     */
    Boolean cbom;

    /**
     * Timeout for CBOM scan (e.g., "4h", "12h").
     */
    String cbomTimeout;

    @JsonIgnore
    @Override
    public boolean isEmpty() {
        return this.equals(new BrewRPMConfig());
    }

}
