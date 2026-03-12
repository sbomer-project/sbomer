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
package org.jboss.sbomer.cli.test.integ.feature.sbom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.pnc.dto.Build;
import org.jboss.sbomer.cli.feature.sbom.ConfigReader;
import org.jboss.sbomer.cli.feature.sbom.client.GitHubClient;
import org.jboss.sbomer.cli.feature.sbom.client.GitLabClient;
import org.jboss.sbomer.cli.feature.sbom.client.GitilesClient;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.features.sbom.config.Config;
import org.jboss.sbomer.core.features.sbom.config.PncBuildConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.ProductConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.fasterxml.jackson.databind.JsonMappingException;

import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;

@QuarkusTest
class ConfigReaderIT {

    @Inject
    ConfigReader configReader;

    private byte[] getTestConfigAsBytes(String fileName) throws IOException {
        return Files.readString(Paths.get("src", "test", "resources", "sbomer-configs", fileName)).getBytes();
    }

    @Nested
    class Gerrit {

        @InjectMock
        @RestClient
        GitilesClient gitilesClient;

        final Build build = Build.builder()
                .id("ARYT3LBXDVYAC")
                .scmUrl("https://code.engineering.redhat.com/gerrit/eclipse/microprofile-graphql.git")
                .scmTag("1.1.0.redhat-00008")
                .build();

        @Test
        void testConfigDoesNotExist() {
            Mockito.when(
                    gitilesClient.fetchFile(
                            "eclipse/microprofile-graphql",
                            "refs/tags/1.1.0.redhat-00008",
                            ".sbomer/config.yaml"))
                    .thenThrow(NotFoundException.class);

            assertNull(configReader.getConfig(build));
        }

        @Test
        void testConfigMultipleProducts() throws IOException {
            Mockito.when(
                    gitilesClient.fetchFile(
                            "eclipse/microprofile-graphql",
                            "refs/tags/1.1.0.redhat-00008",
                            ".sbomer/config.yaml"))
                    .thenReturn(new String(Base64.getEncoder().encode(getTestConfigAsBytes("multi-product.yaml"))));

            assertNotNull(configReader.getConfig(build));
        }

        @Test
        void testInvalidProcessorSlug() throws IOException {
            Mockito.when(
                    gitilesClient.fetchFile(
                            "eclipse/microprofile-graphql",
                            "refs/tags/1.1.0.redhat-00008",
                            ".sbomer/config.yaml"))
                    .thenReturn(
                            new String(
                                    Base64.getEncoder()
                                            .encode(getTestConfigAsBytes("invalid-wrong-processor-slug.yaml"))));

            ApplicationException ex = assertThrows(ApplicationException.class, () -> configReader.getConfig(build));

            assertEquals("Invalid type 'doesntexist' found at path $.products.[0].processors.[0]", ex.getMessage());
            assertEquals(
                    "Could not resolve type id 'doesntexist' as a subtype of `org.jboss.sbomer.core.features.sbom.config.runtime.ProcessorConfig`: known type ids = [default, redhat-product] (for POJO property 'processors')",
                    ((JsonMappingException) ex.getCause()).getOriginalMessage());
        }

        @Test
        void testInvalidConfig() throws IOException {
            Mockito.when(
                    gitilesClient.fetchFile(
                            "eclipse/microprofile-graphql",
                            "refs/tags/1.1.0.redhat-00008",
                            ".sbomer/config.yaml"))
                    .thenReturn(
                            new String(
                                    Base64.getEncoder().encode(getTestConfigAsBytes("invalid-processor-config.yaml"))));

            ApplicationException ex = assertThrows(ApplicationException.class, () -> configReader.getConfig(build));

            assertEquals("Unknown property 'dummy' at path $.products.[0].processors.[0].dummy", ex.getMessage());
            assertTrue(ex.getCause().getMessage().startsWith("Unrecognized field \"dummy\""));
        }

        @Test
        void testOnlyErrataOverride() throws IOException {
            Mockito.when(
                    gitilesClient.fetchFile(
                            "eclipse/microprofile-graphql",
                            "refs/tags/1.1.0.redhat-00008",
                            ".sbomer/config.yaml"))
                    .thenReturn(
                            new String(
                                    Base64.getEncoder().encode(getTestConfigAsBytes("single-errata-override.yaml"))));

            assertNotNull(configReader.getConfig(build));
        }

        @Test
        void testOnlyGeneratorOverride() throws IOException {
            Mockito.when(
                    gitilesClient.fetchFile(
                            "eclipse/microprofile-graphql",
                            "refs/tags/1.1.0.redhat-00008",
                            ".sbomer/config.yaml"))
                    .thenReturn(
                            new String(
                                    Base64.getEncoder()
                                            .encode(getTestConfigAsBytes("single-generator-override.yaml"))));

            Config config = configReader.getConfig(build);

            assertNotNull(config);
            assertEquals("sbomer.jboss.org/v1alpha1", config.getApiVersion());

            assertInstanceOf(PncBuildConfig.class, config);

            ProductConfig productConfig = ((PncBuildConfig) config).getProducts().get(0);
            assertEquals(0, productConfig.getProcessors().size());
            assertEquals("0.0.88", productConfig.getGenerator().getVersion());
        }

    }

    @Nested
    class GitLab {

        @InjectMock
        @RestClient
        GitLabClient gitLabClient;

        final Build build = Build.builder()
                .id("ARYT3LBXDVYAC")
                .scmUrl("https://gitlab.cee.redhat.com/pnc-workspace/eclipse/microprofile-graphql.git")
                .scmTag("1.1.0.redhat-00008")
                .build();

        @BeforeEach
        void configureGitLabHost() {
            configReader.setGitLabHost("gitlab.cee.redhat.com");
        }

        @Test
        void testConfigDoesNotExist() {
            Mockito.when(
                    gitLabClient.fetchFile(
                            "pnc-workspace/eclipse/microprofile-graphql",
                            "1.1.0.redhat-00008",
                            ".sbomer/config.yaml"))
                    .thenThrow(NotFoundException.class);

            assertNull(configReader.getConfig(build));
        }

        @Test
        void testConfigMultipleProducts() throws IOException {
            Mockito.when(
                    gitLabClient.fetchFile(
                            "pnc-workspace/eclipse/microprofile-graphql",
                            "1.1.0.redhat-00008",
                            ".sbomer/config.yaml"))
                    .thenReturn(new String(getTestConfigAsBytes("multi-product.yaml")));

            assertNotNull(configReader.getConfig(build));
        }

        @Test
        void testInvalidProcessorSlug() throws IOException {
            Mockito.when(
                    gitLabClient.fetchFile(
                            "pnc-workspace/eclipse/microprofile-graphql",
                            "1.1.0.redhat-00008",
                            ".sbomer/config.yaml"))
                    .thenReturn(new String(getTestConfigAsBytes("invalid-wrong-processor-slug.yaml")));

            ApplicationException ex = assertThrows(ApplicationException.class, () -> configReader.getConfig(build));

            assertEquals("Invalid type 'doesntexist' found at path $.products.[0].processors.[0]", ex.getMessage());
            assertEquals(
                    "Could not resolve type id 'doesntexist' as a subtype of `org.jboss.sbomer.core.features.sbom.config.runtime.ProcessorConfig`: known type ids = [default, redhat-product] (for POJO property 'processors')",
                    ((JsonMappingException) ex.getCause()).getOriginalMessage());
        }

        @Test
        void testInvalidConfig() throws IOException {
            Mockito.when(
                    gitLabClient.fetchFile(
                            "pnc-workspace/eclipse/microprofile-graphql",
                            "1.1.0.redhat-00008",
                            ".sbomer/config.yaml"))
                    .thenReturn(new String(getTestConfigAsBytes("invalid-processor-config.yaml")));

            ApplicationException ex = assertThrows(ApplicationException.class, () -> configReader.getConfig(build));

            assertEquals("Unknown property 'dummy' at path $.products.[0].processors.[0].dummy", ex.getMessage());
            assertTrue(ex.getCause().getMessage().startsWith("Unrecognized field \"dummy\""));
        }

        @Test
        void testOnlyErrataOverride() throws IOException {
            Mockito.when(
                    gitLabClient.fetchFile(
                            "pnc-workspace/eclipse/microprofile-graphql",
                            "1.1.0.redhat-00008",
                            ".sbomer/config.yaml"))
                    .thenReturn(new String(getTestConfigAsBytes("single-errata-override.yaml")));

            assertNotNull(configReader.getConfig(build));
        }

        @Test
        void testOnlyGeneratorOverride() throws IOException {
            Mockito.when(
                    gitLabClient.fetchFile(
                            "pnc-workspace/eclipse/microprofile-graphql",
                            "1.1.0.redhat-00008",
                            ".sbomer/config.yaml"))
                    .thenReturn(new String(getTestConfigAsBytes("single-generator-override.yaml")));

            Config config = configReader.getConfig(build);

            assertNotNull(config);
            assertInstanceOf(PncBuildConfig.class, config);
            assertEquals("sbomer.jboss.org/v1alpha1", config.getApiVersion());

            ProductConfig productConfig = ((PncBuildConfig) config).getProducts().get(0);
            assertEquals(0, productConfig.getProcessors().size());
            assertEquals("0.0.88", productConfig.getGenerator().getVersion());
        }

        @Test
        void testMoreGitLabUrls() throws IOException {

            Build build2 = Build.builder()
                    .id("ARYT3LBXDVYACCC")
                    .scmUrl("git@gitlab.cee.redhat.com:platform/build-and-release/requirements.git")
                    .scmTag("1.3.0.redhat-00013")
                    .build();

            Build build3 = Build.builder()
                    .id("BBYT3LBXDVYACCC")
                    .scmUrl("https://gitlab.cee.redhat.com/platform/build-and-release/requirements.git")
                    .scmTag("0.3.0.redhat-00003")
                    .build();

            Build build4 = Build.builder()
                    .id("DDYT3LBXDVYACCC")
                    .scmUrl("https://gitlab.cee.redhat.com/fuse-hawtio/hawtio-mirror.git")
                    .scmTag("1.2.3.redhat-00003")
                    .build();

            Mockito.when(
                    gitLabClient.fetchFile(
                            "platform/build-and-release/requirements",
                            "1.3.0.redhat-00013",
                            ".sbomer/config.yaml"))
                    .thenReturn(new String(getTestConfigAsBytes("multi-product.yaml")));

            assertNotNull(configReader.getConfig(build2));

            Mockito.when(
                    gitLabClient.fetchFile(
                            "platform/build-and-release/requirements",
                            "0.3.0.redhat-00003",
                            ".sbomer/config.yaml"))
                    .thenReturn(new String(getTestConfigAsBytes("multi-product.yaml")));

            assertNotNull(configReader.getConfig(build3));

            Mockito.when(
                    gitLabClient.fetchFile("fuse-hawtio/hawtio-mirror", "1.2.3.redhat-00003", ".sbomer/config.yaml"))
                    .thenReturn(new String(getTestConfigAsBytes("multi-product.yaml")));

            assertNotNull(configReader.getConfig(build4));
        }
    }

    @Nested
    class GitHub {

        @InjectMock
        @RestClient
        GitHubClient gitHubClient;

        final Build build = Build.builder()
                .id("ARYT3LBXDVYAC")
                .scmUrl("https://github.ibm.com/pnc-stage/hibernate-hibernate-orm-product.git")
                .scmTag("1.1.0.redhat-00008")
                .build();

        @BeforeEach
        void configureGitHubHost() {
            configReader.setGitHubHost("github.ibm.com");
        }

        @Test
        void testConfigDoesNotExist() {
            Mockito.when(
                    gitHubClient.fetchFile(
                            "pnc-stage",
                            "hibernate-hibernate-orm-product",
                            ".sbomer/config.yaml",
                            "1.1.0.redhat-00008"))
                    .thenThrow(NotFoundException.class);

            assertNull(configReader.getConfig(build));
        }

        @Test
        void testConfigMultipleProducts() throws IOException {
            // GitHub API returns JSON with base64 encoded content
            String base64Content = Base64.getEncoder().encodeToString(getTestConfigAsBytes("multi-product.yaml"));
            String jsonResponse = String.format("{\"content\":\"%s\",\"encoding\":\"base64\"}", base64Content);

            Mockito.when(
                    gitHubClient.fetchFile(
                            "pnc-stage",
                            "hibernate-hibernate-orm-product",
                            ".sbomer/config.yaml",
                            "1.1.0.redhat-00008"))
                    .thenReturn(jsonResponse);

            assertNotNull(configReader.getConfig(build));
        }

        @Test
        void testMoreGitHubUrls() throws IOException {

            Build build2 = Build.builder()
                    .id("ARYT3LBXDVYACCC")
                    .scmUrl("git@github.ibm.com:platform/requirements.git")
                    .scmTag("1.3.0.redhat-00013")
                    .build();

            Build build3 = Build.builder()
                    .id("BBYT3LBXDVYACCC")
                    .scmUrl("https://github.ibm.com/platform/requirements.git")
                    .scmTag("0.3.0.redhat-00003")
                    .build();

            String base64Content = Base64.getEncoder().encodeToString(getTestConfigAsBytes("multi-product.yaml"));
            String jsonResponse = String.format("{\"content\":\"%s\",\"encoding\":\"base64\"}", base64Content);

            Mockito.when(
                    gitHubClient.fetchFile("platform", "requirements", ".sbomer/config.yaml", "1.3.0.redhat-00013"))
                    .thenReturn(jsonResponse);

            assertNotNull(configReader.getConfig(build2));

            Mockito.when(
                    gitHubClient.fetchFile("platform", "requirements", ".sbomer/config.yaml", "0.3.0.redhat-00003"))
                    .thenReturn(jsonResponse);

            assertNotNull(configReader.getConfig(build3));
        }
    }
}
