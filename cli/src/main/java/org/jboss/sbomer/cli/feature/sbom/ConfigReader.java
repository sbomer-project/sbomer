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
package org.jboss.sbomer.cli.feature.sbom;

import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.pnc.dto.Build;
import org.jboss.sbomer.cli.feature.sbom.client.GitHubClient;
import org.jboss.sbomer.cli.feature.sbom.client.GitLabClient;
import org.jboss.sbomer.cli.feature.sbom.client.GitilesClient;
import org.jboss.sbomer.core.errors.ClientException;
import org.jboss.sbomer.core.features.sbom.config.Config;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@ApplicationScoped
@Slf4j
public class ConfigReader {
    private static final String CONFIG_PATH = ".sbomer/config.yaml";

    @Inject
    @RestClient
    GitilesClient gitilesClient;

    @Inject
    @RestClient
    GitLabClient gitLabClient;

    @Inject
    @RestClient
    GitHubClient gitHubClient;

    @ConfigProperty(name = "sbomer.gitlab.host", defaultValue = "gitlab.com")
    @Getter
    @Setter
    String gitLabHost;

    @ConfigProperty(name = "sbomer.github.host", defaultValue = "github.com")
    @Getter
    @Setter
    String gitHubHost;

    @Getter
    final ObjectMapper yamlObjectMapper = ObjectMapperProvider.yaml();

    @Getter
    final ObjectMapper jsonObjectMapper = ObjectMapperProvider.json();

    /**
     * Retrieves the content of the SBOMer config file from a Gerrit server.
     *
     * @param scmUrl the SCM URL
     * @param scmTag the SCM tag
     * @return the base64 decoded content of the config file
     */
    private byte[] getGerritConfigContent(String scmUrl, String scmTag) {
        log.debug("Using Gerrit config provider");

        Pattern pattern = Pattern.compile("gerrit/(.*)\\.git$");
        Matcher matcher = pattern.matcher(scmUrl);

        if (!matcher.find()) {
            throw new ClientException("Invalid URL '{}' for Gerrit SCM", scmUrl);
        }

        String repository = matcher.group(1);

        log.debug("Found Gerrit project: '{}'", repository);

        String base64Config;

        log.debug("Fetching file '{}' from the '{}' GitHub repository with tag '{}'", CONFIG_PATH, repository, scmTag);

        try {
            base64Config = gitilesClient.fetchFile(repository, "refs/tags/" + scmTag, CONFIG_PATH);
        } catch (Exception e) {

            log.debug(
                    "SBOMer configuration file could not be retrieved in the '{}' repository with '{}' tag, ignoring",
                    repository,
                    scmTag,
                    e);

            return new byte[0];
        }

        return Base64.getDecoder().decode(base64Config);
    }

    /**
     * Retrieves the content of the SBOMer config file from a GitLab server.
     *
     * @param scmUrl the SCM URL
     * @param scmTag the SCM tag
     * @return the content of the SBOMer config file
     */
    private byte[] getGitLabConfigContent(String scmUrl, String scmTag) {
        log.debug("Using GitLab config provider");

        // The group can be different from the standard "pnc-workspace"; the repository can have many nested names
        // The regexp below will match, e.g., both git@gitlab.cee.redhat.com:platform/build-and-release/requirements.git
        // and https://gitlab.cee.redhat.com/platform/build-and-release/requirements.git
        Pattern pattern = Pattern.compile(getGitLabHost() + "[:/](.*)\\.git$");
        Matcher matcher = pattern.matcher(scmUrl);

        if (!matcher.find()) {
            throw new ClientException("Invalid URL '{}' for GitLab SCM", scmUrl);
        }

        String project = matcher.group(1);

        log.debug("Found GitLab project: '{}'", project);
        log.debug("Fetching file '{}' from the '{}' GitLab repository with tag '{}'", CONFIG_PATH, project, scmTag);

        try {
            return gitLabClient.fetchFile(project, scmTag, CONFIG_PATH).getBytes();
        } catch (Exception e) {
            log.debug(
                    "SBOMer configuration file could not be retrieved in the '{}' repository with '{}' tag, ignoring",
                    project,
                    scmTag,
                    e);

            return new byte[0];
        }

    }

    private byte[] getGitHubConfigContent(String scmUrl, String scmTag) {

        log.debug("Using GitHub config provider");

        // The regexp below will match, e.g., both git@github.ibm.com:owner/repo.git
        // and https://github.ibm.com/owner/repo.git
        Pattern pattern = Pattern.compile(getGitHubHost() + "[:/](.*?)/(.*?)\\.git$");
        Matcher matcher = pattern.matcher(scmUrl);
        if (!matcher.find()) {
            throw new ClientException("Invalid URL '{}' for GitHub SCM", scmUrl);
        }

        String owner = matcher.group(1);
        String repo = matcher.group(2);

        log.debug("Found GitHub repository: '{}/{}'", owner, repo);

        String base64Config;

        log.debug(
                "Fetching file '{}' from the '{}/{}' GitHub repository with tag '{}'",
                CONFIG_PATH,
                owner,
                repo,
                scmTag);

        try {
            String jsonResponse = gitHubClient.fetchFile(owner, repo, CONFIG_PATH, scmTag);

            // GitHub API returns JSON with base64 encoded content
            // Parse the JSON to extract the content field
            JsonNode jsonNode = jsonObjectMapper.readTree(jsonResponse);
            base64Config = jsonNode.get("content").asText();
        } catch (Exception e) {
            log.debug(
                    "SBOMer configuration file could not be retrieved in the '{}/{}' repository with '{}' tag, ignoring",
                    owner,
                    repo,
                    scmTag,
                    e);

            return new byte[0];
        }

        return Base64.getDecoder().decode(base64Config);
    }

    public Config getConfig(Build build) {

        String scmUrl = build.getScmUrl();
        String scmTag = build.getScmTag();

        if (org.jboss.pnc.enums.BuildStatus.NO_REBUILD_REQUIRED.equals(build.getStatus())) {
            scmUrl = build.getNoRebuildCause().getScmUrl();
            scmTag = build.getNoRebuildCause().getScmTag();
        }

        byte[] configContent;

        if (scmUrl.contains("gerrit")) {
            configContent = getGerritConfigContent(scmUrl, scmTag);
        } else if (scmUrl.contains("gitlab")) {
            configContent = getGitLabConfigContent(scmUrl, scmTag);
        } else if (scmUrl.contains("github")) {
            configContent = getGitHubConfigContent(scmUrl, scmTag);
        } else {
            throw new ClientException(
                    "Unable to determine the project from the SCM url: '{}' from PNC build '{}'",
                    scmUrl,
                    build.getId());
        }

        if (configContent.length == 0) {
            log.warn("Config file not found or failed to retrieve it, ignoring");
            return null;
        }

        return Config.fromBytes(configContent);
    }
}
