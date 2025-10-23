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
package org.jboss.sbomer.cli.test.integ.feature.sbom.command.processor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Commit;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.hamcrest.CoreMatchers;
import org.jboss.pnc.dto.Artifact;
import org.jboss.pnc.dto.Build;
import org.jboss.pnc.dto.Environment;
import org.jboss.pnc.dto.SCMRepository;
import org.jboss.sbomer.cli.feature.sbom.client.CachitoClient;
import org.jboss.sbomer.cli.feature.sbom.command.AbstractMavenGenerateCommand;
import org.jboss.sbomer.cli.feature.sbom.command.DefaultProcessCommand;
import org.jboss.sbomer.cli.feature.sbom.command.GenerateCommand;
import org.jboss.sbomer.cli.feature.sbom.command.ProcessCommand;
import org.jboss.sbomer.cli.feature.sbom.service.KojiService;
import org.jboss.sbomer.core.features.sbom.enums.ProcessorType;
import org.jboss.sbomer.core.features.sbom.provider.BuildFinderConfigProvider;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;
import org.jboss.sbomer.core.pnc.PncService;
import org.jboss.sbomer.core.test.TestResources;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@QuarkusTest
class DefaultProcessCommandIT {
    @Inject
    ObjectMapper objectMapper;

    @InjectMock
    PncService pncService;

    @InjectMock
    KojiService kojiService;

    @InjectMock
    CachitoClient cachitoClient;

    @InjectMock
    BuildFinderConfigProvider buildFinderConfigProvider;

    @Inject
    DefaultProcessCommand command;

    private JsonNode generateBom() throws IOException {
        String bomJson = TestResources.asString("boms/valid.json");
        return objectMapper.readTree(bomJson);
    }

    private Build generateBuild() {
        return Build.builder()
                .id("BBVVCC")
                .environment(
                        Environment.builder()
                                .systemImageId("imageid")
                                .systemImageRepositoryUrl("systemImageRepositoryUrl")
                                .build())
                .scmRepository(SCMRepository.builder().externalUrl("externalurl").build())
                .scmTag("scmtag")
                .scmRevision("scmrevision")
                .scmUrl("scmurl")
                .build();
    }

    private Artifact generateArtifact(String purl, String sha256) {
        return Artifact.builder()
                .id("AA1122")
                .md5("md5")
                .sha1("sha1")
                .sha256(sha256)
                .purl(purl)
                .publicUrl("artifactpublicurl")
                .originUrl("originurl")
                .build(generateBuild())
                .build();
    }

    private List<String> getExternalReferences(Component component, ExternalReference.Type type) {
        return SbomUtils.getExternalReferences(component, type).stream().map(ExternalReference::getUrl).toList();
    }

    private void assertExternalReference(Component component, ExternalReference.Type type, String value) {
        assertThat(getExternalReferences(component, type), CoreMatchers.hasItem(value));
    }

    @Test
    void shouldReturnCorrectImplementationType() {
        log.info("test: shouldReturnCorrectImplementationType");
        assertEquals(ProcessorType.DEFAULT, command.getImplementationType());
    }

    @Test
    void shouldManipulateBomContent() throws Exception {
        log.info("test: shouldManipulateBomContent");

        Mockito.when(pncService.getApiUrl()).thenReturn("apiurl");

        String[] componentPurls = { "pkg:maven/commons-io/commons-io@2.6.0.redhat-00001?type=jar",
                "pkg:maven/com.aayushatharva.brotli4j/brotli4j@1.8.0.redhat-00003?type=jar",
                "pkg:maven/org.eclipse.microprofile.graphql/microprofile-graphql-api@1.1.0.redhat-00008?type=jar",
                "pkg:maven/org.eclipse.microprofile.graphql/microprofile-graphql-tck@1.1.0.redhat-00008?type=jar" };

        Bom baseBom = SbomUtils.fromJsonNode(generateBom());

        for (String purl : componentPurls) {
            Optional<Component> componentOpt = SbomUtils.findComponentWithPurl(purl, baseBom);
            assertTrue(componentOpt.isPresent());
            Component component = componentOpt.get();

            assertEquals(2, component.getProperties().size());

            Optional<String> sha256 = SbomUtils.getHash(component, Hash.Algorithm.SHA_256);
            String sha = sha256.orElse(null);
            Mockito.when(pncService.getArtifact(purl, sha256, Optional.empty(), Optional.empty()))
                    .thenReturn(generateArtifact(purl, sha));
        }

        DefaultProcessCommand spiedCommand = spy(command);
        stubBuildId(spiedCommand);

        Bom bom = spiedCommand.doProcess(SbomUtils.fromJsonNode(generateBom()));

        for (String purl : componentPurls) {
            Optional<Component> componentOpt = SbomUtils.findComponentWithPurl(purl, bom);
            assertTrue(componentOpt.isPresent());
            Component component = componentOpt.get();

            List<String> hashes = component.getHashes().stream().map(Hash::getValue).toList();

            assertEquals(3, hashes.size());
            assertEquals(2, component.getProperties().size());

            assertExternalReference(
                    component,
                    ExternalReference.Type.BUILD_SYSTEM,
                    "https://apiurl/pnc-rest/v2/builds/BBVVCC");
            assertExternalReference(
                    component,
                    ExternalReference.Type.DISTRIBUTION,
                    "https://maven.repository.redhat.com/ga/");
            assertExternalReference(component, ExternalReference.Type.BUILD_META, "systemImageRepositoryUrl/imageid");

            assertEquals("Red Hat", component.getPublisher());
            assertEquals("Red Hat", component.getSupplier().getName());
            assertEquals(List.of("https://www.redhat.com"), component.getSupplier().getUrls());

            Commit commit = component.getPedigree().getCommits().get(0);

            assertEquals("scmrevision", commit.getUid());
            assertEquals("scmurl#scmtag", commit.getUrl());
        }
    }

    @Test
    void shouldHandleArtifactsBuiltOutsideOfPNC() throws Exception {
        log.info("test: shouldHandleArtifactsBuiltOutsideOfPNC");

        Mockito.when(pncService.getApiUrl()).thenReturn("apiurl");

        String[] componentPurls = { "pkg:maven/com.aayushatharva.brotli4j/brotli4j@1.8.0.redhat-00003?type=jar",
                "pkg:maven/org.eclipse.microprofile.graphql/microprofile-graphql-api@1.1.0.redhat-00008?type=jar",
                "pkg:maven/org.eclipse.microprofile.graphql/microprofile-graphql-tck@1.1.0.redhat-00008?type=jar" };

        String[] sha256s = { "75efe10bfb9d1e96c320ab9ca9daddc2aebfcc9d017be651f60cb41ed100f23f",
                "8e23987f69b896c23e3b724cd7512a9b39a2ee6f53dc9ba1774acfe0994a95e3",
                "98b67e15e3fe39e4f8721bdcfda99f19e570426d8960f73f8d5fe1414ff2fab3" };

        for (int i = 0; i < 3; i++) {
            Mockito.when(
                    pncService.getArtifact(
                            componentPurls[i],
                            Optional.of(sha256s[i]),
                            Optional.empty(),
                            Optional.empty()))
                    .thenReturn(generateArtifact(componentPurls[i], sha256s[i]));
        }

        String specialPurl = "pkg:maven/commons-io/commons-io@2.6.0.redhat-00001?type=jar";
        Artifact artifact = Artifact.builder()
                .id("AA1122")
                .md5("md5")
                .sha1("sha1")
                .sha256("122dd093db60b5fafcb428b28569aa72993e2a2c63d3d87b7dcc076bdebd8a71")
                .purl(specialPurl)
                .publicUrl("artifactpublicurl")
                .originUrl("originurl")
                .build();

        Mockito.when(
                pncService.getArtifact(
                        specialPurl,
                        Optional.of("122dd093db60b5fafcb428b28569aa72993e2a2c63d3d87b7dcc076bdebd8a71"),
                        Optional.empty(),
                        Optional.empty()))
                .thenReturn(artifact);

        DefaultProcessCommand spiedCommand = spy(command);
        stubBuildId(spiedCommand);

        Bom bom = spiedCommand.doProcess(SbomUtils.fromJsonNode(generateBom()));

        Optional<Component> componentOpt = SbomUtils.findComponentWithPurl(specialPurl, bom);
        assertTrue(componentOpt.isPresent());
        Component component = componentOpt.get();

        assertEquals(2, component.getProperties().size());

        assertEquals("Red Hat", component.getPublisher());
        assertEquals("Red Hat", component.getSupplier().getName());
        assertEquals(List.of("https://www.redhat.com"), component.getSupplier().getUrls());

        assertExternalReference(
                component,
                ExternalReference.Type.DISTRIBUTION,
                "https://maven.repository.redhat.com/ga/");

        // The manifest will contain also a non-enriched build system entry
        assertExternalReference(component, ExternalReference.Type.BUILD_SYSTEM, "https://builds.apache.org/");

        assertEquals(0, getExternalReferences(component, ExternalReference.Type.BUILD_META).size());
    }

    private void stubBuildId(DefaultProcessCommand command) {
        // OMG!
        GenerateCommand mockGenerateCommand = mock(GenerateCommand.class);
        when(mockGenerateCommand.getBuildId()).thenReturn("BBVVCC");
        AbstractMavenGenerateCommand mockAbstractMavenGenerateCommand = mock(AbstractMavenGenerateCommand.class);

        when(mockAbstractMavenGenerateCommand.getParent()).thenReturn(mockGenerateCommand);
        ProcessCommand mockProcessCommand = mock(ProcessCommand.class);
        when(mockProcessCommand.getParent()).thenReturn(mockAbstractMavenGenerateCommand);

        doReturn(mockProcessCommand).when(command).getParent();
    }
}
