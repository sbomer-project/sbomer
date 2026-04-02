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

import org.eclipse.microprofile.rest.client.annotation.RegisterProvider;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;

/**
 * Client used to interact with the SCM (GitHub Enterprise) to fetch the config file for a particular build. The /api/v3
 * path is included in the endpoint path for GitHub Enterprise compatibility.
 */
@ApplicationScoped
@RegisterRestClient(configKey = "github")
@RegisterProvider(GitHubClientRequestFilter.class)
@Path("/api/v3")
public interface GitHubEnterpriseClient {
    /**
     * Fetch content of the file at the provided {@code path} in the GitHub repository {@code owner}/{@code repo}
     * identified by the {@code ref}.
     *
     * @param owner The repository owner
     * @param repo The repository name
     * @param path The path to the file
     * @param ref The reference, for example, a tag: {@code 1.0.0.Final}
     * @return JSON response containing base64 encoded content of the file.
     */
    @GET
    @Path("/repos/{owner}/{repo}/contents/{path}")
    String fetchFile(
            @PathParam("owner") String owner,
            @PathParam("repo") String repo,
            @PathParam("path") String path,
            @QueryParam("ref") String ref);
}
