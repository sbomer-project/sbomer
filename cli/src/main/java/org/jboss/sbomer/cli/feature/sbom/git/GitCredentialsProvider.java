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
package org.jboss.sbomer.cli.feature.sbom.git;

import java.util.Optional;

import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import jakarta.enterprise.context.ApplicationScoped;
import lombok.extern.slf4j.Slf4j;

@ApplicationScoped
@Slf4j
public class GitCredentialsProvider {

    @ConfigProperty(name = "sbomer.github.token")
    Optional<String> githubToken;

    @ConfigProperty(name = "sbomer.github.host", defaultValue = "github.com")
    String githubHost;

    /**
     * Get credentials provider for the given SCM URL. Returns null if no credentials are configured or needed.
     *
     * @param scmUrl The Git repository URL
     * @return CredentialsProvider or null for public repos
     */
    public CredentialsProvider getCredentials(String scmUrl) {
        if (scmUrl == null || scmUrl.isEmpty()) {
            return null;
        }

        // Normalize URL for comparison
        String normalizedUrl = scmUrl.toLowerCase();

        // GitHub authentication
        if (isGitHubUrl(normalizedUrl)) {
            if (githubToken.isPresent()) {
                log.debug("Using GitHub token authentication for: {}", scmUrl);
                // For GitHub, username can be anything when using token
                return new UsernamePasswordCredentialsProvider("token", githubToken.get());
            } else {
                log.debug("No GitHub token configured, attempting public clone from: {}", scmUrl);
                return null;
            }
        }

        log.debug("No credentials configured for SCM host, attempting public clone from: {}", scmUrl);
        return null;
    }

    /**
     * Check if URL is a GitHub URL (including GitHub Enterprise)
     */
    private boolean isGitHubUrl(String url) {
        return url.contains(githubHost.toLowerCase()) || url.contains("github.com")
                || url.contains("git@github.com") || url.contains("git@" + githubHost.toLowerCase());
    }

    /**
     * Check if credentials are available for the given URL
     */
    public boolean hasCredentials(String scmUrl) {
        return getCredentials(scmUrl) != null;
    }
}

