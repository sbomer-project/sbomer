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
package org.jboss.sbomer.cli.test.unit.feature.sbom.download;

import static org.jboss.sbomer.cli.feature.sbom.command.download.BrewSourcesDownloadCommand.CONTAINER_PROPERTY_SYFT_IMAGE_LABEL_COMPONENT;
import static org.jboss.sbomer.cli.feature.sbom.command.download.BrewSourcesDownloadCommand.CONTAINER_PROPERTY_SYFT_IMAGE_LABEL_RELEASE;
import static org.jboss.sbomer.cli.feature.sbom.command.download.BrewSourcesDownloadCommand.CONTAINER_PROPERTY_SYFT_IMAGE_LABEL_VERSION;
import static org.jboss.sbomer.cli.feature.sbom.service.KojiService.REMOTE_SOURCE_DELIMITER;
import static org.jboss.sbomer.cli.feature.sbom.service.KojiService.REMOTE_SOURCE_PREFIX;
import static org.jboss.sbomer.cli.feature.sbom.service.KojiService.SOURCES_FILE_ARCHIVE_SUFFIX;
import static org.jboss.sbomer.cli.feature.sbom.service.KojiService.SOURCES_FILE_METADATA_SUFFIX;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Metadata;
import org.jboss.pnc.build.finder.koji.ClientSession;
import org.jboss.sbomer.cli.feature.sbom.client.KojiDownloadClient;
import org.jboss.sbomer.cli.feature.sbom.command.download.BrewSourcesDownloadCommand;
import org.jboss.sbomer.cli.feature.sbom.service.KojiService;
import org.jboss.sbomer.cli.test.utils.KojiBuildInfoFactory;
import org.jboss.sbomer.core.errors.ApplicationException;
import org.jboss.sbomer.core.test.TestResources;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.redhat.red.build.koji.KojiClientException;
import com.redhat.red.build.koji.model.xmlrpc.KojiBuildInfo;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

class BrewSourcesDownloadCommandTest {

    static class BrewSourcesDownloadCommandAlt extends BrewSourcesDownloadCommand {
        @Override
        public void doDownload(Path outputDir) {
            super.doDownload(outputDir);
        }

        @Override
        public String findNvr(Bom bom) {
            return super.findNvr(bom);
        }
    }

    @TempDir
    Path tmpDir;
    Path image = null;

    static final String BOMS = "boms/";
    static final String IMAGE = "image.json";
    static final String NAME = "amqstreams-console-ui-container";
    static final String VERSION = "2.7.0";
    static final String RELEASE = "8.1718294415";
    static final String SOURCES_NAME = "amqstreams-console-ui";
    static final int BUILD_ID = 123;
    static final int PACKAGE_ID = 456;

    BrewSourcesDownloadCommandAlt brewSourcesDownloadCommand;
    KojiService kojiService;

    final ClientSession kojiSession = mock(ClientSession.class);
    final KojiDownloadClient kojiDownloadClient = mock(KojiDownloadClient.class);

    @BeforeEach
    void init() throws IOException {
        image = tmpDir.resolve(IMAGE);
        Files.writeString(image, TestResources.asString(BOMS + IMAGE));
        kojiService = new KojiService();
        kojiService.setKojiSession(kojiSession);
        kojiService.setKojiDownloadClient(kojiDownloadClient);
        brewSourcesDownloadCommand = new BrewSourcesDownloadCommandAlt();
        brewSourcesDownloadCommand.setPath(image);
        brewSourcesDownloadCommand.setKojiService(kojiService);
    }

    @Test
    void testDownload() throws KojiClientException, IOException {
        KojiBuildInfo buildInfo = createBuildInfo(SOURCES_NAME);
        byte[] archiveContent = "foo".getBytes();
        Response archiveResponse = Response
                .ok(new ByteArrayInputStream(archiveContent), MediaType.APPLICATION_OCTET_STREAM)
                .build();
        byte[] metadataContent = "bar".getBytes();
        Response metadataResponse = Response
                .ok(new ByteArrayInputStream(metadataContent), MediaType.APPLICATION_OCTET_STREAM)
                .build();
        String remoteSourcesName = REMOTE_SOURCE_PREFIX + REMOTE_SOURCE_DELIMITER + SOURCES_NAME;

        when(kojiSession.getBuild(any())).thenReturn(List.of(buildInfo));
        when(
                kojiDownloadClient
                        .downloadSourcesFile(NAME, VERSION, RELEASE, remoteSourcesName + SOURCES_FILE_ARCHIVE_SUFFIX))
                .thenReturn(archiveResponse);
        when(
                kojiDownloadClient
                        .downloadSourcesFile(NAME, VERSION, RELEASE, remoteSourcesName + SOURCES_FILE_METADATA_SUFFIX))
                .thenReturn(metadataResponse);

        brewSourcesDownloadCommand.doDownload(tmpDir);
        Path archivePath = tmpDir.resolve(remoteSourcesName + SOURCES_FILE_ARCHIVE_SUFFIX);
        Path metadataPath = tmpDir.resolve(remoteSourcesName + SOURCES_FILE_METADATA_SUFFIX);

        assertTrue(Files.exists(archivePath));
        assertTrue(Files.exists(metadataPath));
        assertArrayEquals(archiveContent, Files.readAllBytes(archivePath));
        assertArrayEquals(metadataContent, Files.readAllBytes(metadataPath));
    }

    @Test
    void testDownloadNoRemoteSourcesName() throws KojiClientException, IOException {
        KojiBuildInfo buildInfo = createBuildInfo(null);
        byte[] archiveContent = "123".getBytes();
        Response archiveResponse = Response
                .ok(new ByteArrayInputStream(archiveContent), MediaType.APPLICATION_OCTET_STREAM)
                .build();
        byte[] metadataContent = "abc".getBytes();
        Response metadataResponse = Response
                .ok(new ByteArrayInputStream(metadataContent), MediaType.APPLICATION_OCTET_STREAM)
                .build();
        String remoteSourcesName = REMOTE_SOURCE_PREFIX;

        when(kojiSession.getBuild(any())).thenReturn(List.of(buildInfo));
        when(
                kojiDownloadClient
                        .downloadSourcesFile(NAME, VERSION, RELEASE, remoteSourcesName + SOURCES_FILE_ARCHIVE_SUFFIX))
                .thenReturn(archiveResponse);
        when(
                kojiDownloadClient
                        .downloadSourcesFile(NAME, VERSION, RELEASE, remoteSourcesName + SOURCES_FILE_METADATA_SUFFIX))
                .thenReturn(metadataResponse);

        brewSourcesDownloadCommand.doDownload(tmpDir);
        Path archivePath = tmpDir.resolve(remoteSourcesName + SOURCES_FILE_ARCHIVE_SUFFIX);
        Path metadataPath = tmpDir.resolve(remoteSourcesName + SOURCES_FILE_METADATA_SUFFIX);

        assertTrue(Files.exists(archivePath));
        assertTrue(Files.exists(metadataPath));
        assertArrayEquals(archiveContent, Files.readAllBytes(archivePath));
        assertArrayEquals(metadataContent, Files.readAllBytes(metadataPath));
    }

    @Test
    void testDownloadNoRemoteSources() throws KojiClientException, IOException {
        KojiBuildInfo buildInfo = createBuildInfoNoRemoteSources();

        when(kojiSession.getBuild(any())).thenReturn(List.of(buildInfo));

        brewSourcesDownloadCommand.doDownload(tmpDir);

        try (Stream<Path> files = Files.list(tmpDir)) {
            boolean fileExists = files.filter(Files::isRegularFile)
                    .anyMatch(
                            path -> path.toString().endsWith(SOURCES_FILE_ARCHIVE_SUFFIX)
                                    || (!path.toString().endsWith(IMAGE)
                                            && path.toString().endsWith(SOURCES_FILE_METADATA_SUFFIX)));
            assertFalse(fileExists);
        }
    }

    @Test
    void testDownloadDoesNotExist() throws KojiClientException {
        KojiBuildInfo buildInfo = createBuildInfo(SOURCES_NAME);
        Response response = Response
                .status(Response.Status.NOT_FOUND.getStatusCode(), Response.Status.NOT_FOUND.getReasonPhrase())
                .build();

        when(kojiSession.getBuild(any())).thenReturn(List.of(buildInfo));
        when(kojiDownloadClient.downloadSourcesFile(any(), any(), any(), any())).thenReturn(response);

        ApplicationException ex = assertThrows(
                ApplicationException.class,
                () -> brewSourcesDownloadCommand.doDownload(tmpDir));
        assertEquals("Failed to download sources file: HTTP 404", ex.getMessage());
    }

    @Test
    void testErrorDownloading() throws KojiClientException {
        KojiBuildInfo buildInfo = createBuildInfo(SOURCES_NAME);

        when(kojiSession.getBuild(any())).thenReturn(List.of(buildInfo));
        when(kojiDownloadClient.downloadSourcesFile(any(), any(), any(), any())).thenThrow(new RuntimeException());

        ApplicationException ex = assertThrows(
                ApplicationException.class,
                () -> brewSourcesDownloadCommand.doDownload(tmpDir));
        assertEquals("Failed to download sources archive or metadata file", ex.getMessage());
    }

    @Test
    void testFindNvrEmptyBom() {
        Bom bom = new Bom();
        Metadata metadata = new Metadata();
        metadata.setProperties(List.of());
        bom.setMetadata(metadata);

        ApplicationException ex = assertThrows(
                ApplicationException.class,
                () -> brewSourcesDownloadCommand.findNvr(bom));

        assertEquals(
                "Missing required properties in main component: "
                        + String.join(
                                ", ",
                                List.of(
                                        CONTAINER_PROPERTY_SYFT_IMAGE_LABEL_COMPONENT,
                                        CONTAINER_PROPERTY_SYFT_IMAGE_LABEL_VERSION,
                                        CONTAINER_PROPERTY_SYFT_IMAGE_LABEL_RELEASE))
                        + ". Unable to download sources archive and metadata for this container image",
                ex.getMessage());
    }

    @Test
    void testNoBuildInfo() throws KojiClientException, IOException {
        when(kojiSession.getBuild(any())).thenReturn(Collections.emptyList());

        brewSourcesDownloadCommand.doDownload(tmpDir);

        try (Stream<Path> files = Files.list(tmpDir)) {
            boolean fileExists = files.filter(Files::isRegularFile)
                    .anyMatch(
                            path -> path.toString().endsWith(SOURCES_FILE_ARCHIVE_SUFFIX)
                                    || (!path.toString().endsWith(IMAGE)
                                            && path.toString().endsWith(SOURCES_FILE_METADATA_SUFFIX)));
            assertFalse(fileExists);
        }
    }

    @Test
    void testFailedToDownloadBuildInfo() throws KojiClientException {
        doThrow(new KojiClientException("A reason")).when(kojiSession).getBuild(any());

        ApplicationException ex = assertThrows(
                ApplicationException.class,
                () -> brewSourcesDownloadCommand.doDownload(tmpDir));

        assertEquals("Lookup in Brew failed", ex.getMessage());
    }

    KojiBuildInfo createBuildInfo(String remoteSourcesName) {
        return KojiBuildInfoFactory
                .withRemoteSources(new KojiBuildInfo(BUILD_ID, PACKAGE_ID, NAME, VERSION, RELEASE), remoteSourcesName);
    }

    KojiBuildInfo createBuildInfoNoRemoteSources() {
        return KojiBuildInfoFactory.withRemoteSources(new KojiBuildInfo(BUILD_ID, PACKAGE_ID, NAME, VERSION, RELEASE));
    }

}
