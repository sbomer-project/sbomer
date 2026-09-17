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
package org.jboss.sbomer.service.feature.sbom.atlas;

import org.eclipse.microprofile.rest.client.annotation.ClientHeaderParam;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

import io.quarkus.oidc.client.filter.OidcClientFilter;
import jakarta.enterprise.context.ApplicationScoped;

/**
 * Info client for the Atlas instance storing build manifests. Shares the {@code atlas-build} configuration (and thus
 * the base URL) with {@link AtlasBuildClient}.
 */
@RegisterRestClient(configKey = "atlas-build")
@OidcClientFilter
@ApplicationScoped
@ClientHeaderParam(name = "User-Agent", value = "SBOMer")
public interface AtlasBuildInfoClient extends AtlasInfoClient {

}
