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
package org.jboss.sbomer.core.test.unit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.jboss.sbomer.core.features.sbom.utils.commandline.maven.MavenCommandLineParser;
import org.jboss.sbomer.core.test.TestResources;
import org.junit.jupiter.api.Test;

class MavenCommandLineParserTest {

    @Test
    void windupParentTest() throws IOException, IllegalArgumentException {
        String script = TestResources.asString("maven/AY6LV5YSDRQAM.sh");

        MavenCommandLineParser lineParser = MavenCommandLineParser.build().launder(script);
        assertEquals(2, lineParser.getProfiles().size());
        assertEquals(1, lineParser.getProperties().size());
        assertEquals(0, lineParser.getProjects().size());
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-DskipTests"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Pmtr,mta"));
        assertFalse(lineParser.getRebuiltMvnCommandScript().contains("-DnpmRegistryURL=\"$npmRegistryURL\""));
    }

    @Test
    void windupRulesetsTest() throws IOException, IllegalArgumentException {
        String script = TestResources.asString("maven/AY6LV5YSDRQAA.sh");

        MavenCommandLineParser lineParser = MavenCommandLineParser.build().launder(script);
        assertEquals(2, lineParser.getProfiles().size());
        assertEquals(2, lineParser.getProperties().size());
        assertEquals(0, lineParser.getProjects().size());
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-DskipTests=true"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Pmtr,mta"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-DskipThemeWindup=true"));
    }

    @Test
    @SuppressWarnings({ "java:S5852", "java:S2068" })
    void windupMtrCliTest() throws IOException, IllegalArgumentException {
        String script = TestResources.asString("maven/AY6LV5YSDRQAC.sh");

        MavenCommandLineParser lineParser = MavenCommandLineParser.build().launder(script);
        assertEquals(1, lineParser.getProfiles().size());
        assertEquals(3, lineParser.getProperties().size());
        assertEquals(0, lineParser.getProjects().size());
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-DskipTests=true"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Pmtr"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-DskipThemeWindup=true"));
        assertFalse(lineParser.getRebuiltMvnCommandScript().contains("-Dhttp.proxyHost=${proxyServer}"));
        assertFalse(lineParser.getRebuiltMvnCommandScript().contains("-Dhttp.proxyPort=${proxyPort}"));
        assertFalse(lineParser.getRebuiltMvnCommandScript().contains("-Dhttp.proxyUser=${proxyUsername}"));
        assertFalse(lineParser.getRebuiltMvnCommandScript().contains("-Dhttp.proxyPassword=${accessToken}"));
        assertTrue(
                lineParser.getRebuiltMvnCommandScript()
                        .contains("-Dorg.apache.maven.user-settings=/usr/share/maven/conf/settings.xml"));
    }

    @Test
    @SuppressWarnings({ "java:S5852", "java:S2068" })
    void windupWebParentTest() throws IOException, IllegalArgumentException {
        String script = TestResources.asString("maven/AY6LV5YSDRQAE.sh");

        MavenCommandLineParser lineParser = MavenCommandLineParser.build().launder(script);
        assertEquals(0, lineParser.getProfiles().size());
        assertEquals(5, lineParser.getProperties().size());
        assertEquals(1, lineParser.getProjects().size());
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-pl !tests,!tests/wildfly-dist"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-DskipTests"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Ddownstream=mtr"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Dwebpack.environment=production "));
        assertFalse(lineParser.getRebuiltMvnCommandScript().contains("-Dhttp.proxyHost=${proxyServer}"));
        assertFalse(lineParser.getRebuiltMvnCommandScript().contains("-Dhttp.proxyPort=${proxyPort}"));
        assertFalse(lineParser.getRebuiltMvnCommandScript().contains("-Dhttp.proxyUser=${proxyUsername}"));
        assertFalse(lineParser.getRebuiltMvnCommandScript().contains("-Dhttp.proxyPassword=${accessToken}"));
        assertTrue(
                lineParser.getRebuiltMvnCommandScript()
                        .contains("-Dorg.apache.maven.user-settings=/usr/share/maven/conf/settings.xml"));
        assertFalse(lineParser.getRebuiltMvnCommandScript().contains("-DnpmRegistryURL=\"$npmRegistryURL\""));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-DnpmArgs=--strict-ssl=false"));
    }

    @Test
    void windupOpenShiftParentTest() throws IOException, IllegalArgumentException {
        String script = TestResources.asString("maven/AY6LV5YSDRQAG.sh");

        MavenCommandLineParser lineParser = MavenCommandLineParser.build().launder(script);
        assertEquals(0, lineParser.getProfiles().size());
        assertEquals(3, lineParser.getProperties().size());
        assertEquals(0, lineParser.getProjects().size());
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-DskipTests"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Djkube.skip"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Ddownstream=mtr"));
    }

    @Test
    void windupMtrWebDistributionTest() throws IOException, IllegalArgumentException {
        String script = TestResources.asString("maven/AY6LV5YSDRQAI.sh");

        MavenCommandLineParser lineParser = MavenCommandLineParser.build().launder(script);
        assertEquals(0, lineParser.getProfiles().size());
        assertEquals(8, lineParser.getProperties().size());
        assertEquals(0, lineParser.getProjects().size());
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Ddownstream=mtr"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-DskipTests"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Dwildfly.http.port=8081"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Dwebpack.environment=production"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Dwildfly.groupId=jboss-eap"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Dwildfly.artifactId=jboss-eap-dist"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Dversion.wildfly=7.4.10.GA"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Dwildfly.directory=jboss-eap-7.4"));
    }

    @Test
    void windupMtrMavenPluginTest() throws IOException, IllegalArgumentException {
        String script = TestResources.asString("maven/AY6LV5YSDRQAK.sh");

        MavenCommandLineParser lineParser = MavenCommandLineParser.build().launder(script);
        assertEquals(1, lineParser.getProfiles().size());
        assertEquals(2, lineParser.getProperties().size());
        assertEquals(0, lineParser.getProjects().size());
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Pmtr"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-DskipTests=true"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-DskipThemeWindup=true"));
    }

    @Test
    void windupOperatorTest() throws IOException, IllegalArgumentException {
        String script = TestResources.asString("maven/AY6LV5YSLRQAA.sh");

        MavenCommandLineParser lineParser = MavenCommandLineParser.build().launder(script);
        assertEquals(1, lineParser.getProfiles().size());
        assertEquals(4, lineParser.getProperties().size());
        assertEquals(0, lineParser.getProjects().size());
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Pnative"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-DskipTests=true"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Ddownstream=mtr"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Dquarkus.native.container-build=false"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Dquarkus.native.container-runtime="));
    }

    @Test
    void tackleDivaCoreTest() throws IOException, IllegalArgumentException {
        String script = TestResources.asString("maven/AY6LV5YSLRQAC.sh");

        MavenCommandLineParser lineParser = MavenCommandLineParser.build().launder(script);
        assertEquals(0, lineParser.getProfiles().size());
        assertEquals(1, lineParser.getProperties().size());
        assertEquals(0, lineParser.getProjects().size());
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-DskipTests=true"));
    }

    @Test
    void jwsTomcatTest() throws IOException, IllegalArgumentException {
        String script = TestResources.asString("maven/A3L53ZF72MYAA.sh");

        MavenCommandLineParser lineParser = MavenCommandLineParser.build().launder(script);
        assertEquals(0, lineParser.getProfiles().size());
        assertEquals(3, lineParser.getProperties().size());
        assertEquals(0, lineParser.getProjects().size());
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-DrepoReportingRemoval=true"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Dmaven.test.failure.ignore=true"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-DversionIncrementalSuffix=redhat"));

        assertEquals(
                "mvn -C -Dmaven.test.failure.ignore=true -DversionIncrementalSuffix=redhat -DrepoReportingRemoval=true",
                lineParser.getRebuiltMvnCommandScript());
    }

    @Test
    void tackleDoubleMvnCommandTest() throws IOException, IllegalArgumentException {
        String script = TestResources.asString("maven/BAZAPVSUDEYAE.sh");

        MavenCommandLineParser lineParser = MavenCommandLineParser.build().launder(script);
        assertEquals(0, lineParser.getProfiles().size());
        assertEquals(3, lineParser.getProperties().size());
        assertEquals(0, lineParser.getProjects().size());
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-DskipTests=true"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Dtycho.strictVersions=false"));
        assertTrue(lineParser.getRebuiltMvnCommandScript().contains("-Dtycho.disableP2Mirrors=true"));
        assertFalse(lineParser.getRebuiltMvnCommandScript().contains("-Dhttp.proxyHost=${proxyServer}"));
        assertFalse(lineParser.getRebuiltMvnCommandScript().contains("-Dhttp.proxyPort=${proxyPort}"));
        assertFalse(lineParser.getRebuiltMvnCommandScript().contains("-Dhttp.proxyUser=${proxyUsername}"));
        assertFalse(lineParser.getRebuiltMvnCommandScript().contains("-Dhttp.proxyPassword=${accessToken}"));
    }

    @Test
    void tackleAlternatePomFileTest() throws IllegalArgumentException {
        String script = "mvn deploy -f productized/logic/pom.xml";

        MavenCommandLineParser lineParser = MavenCommandLineParser.build().launder(script);
        assertEquals(0, lineParser.getProfiles().size());
        assertEquals(0, lineParser.getProperties().size());
        assertEquals(0, lineParser.getProjects().size());
        assertNotNull(lineParser.getAlternatePomFile());
        assertEquals("productized/logic/pom.xml", lineParser.getAlternatePomFile());
    }

    @Test
    void indyMvnTest() throws IllegalArgumentException {
        String script = "mvn -f jaxb-ri/pom.xml -DaltDeploymentRepository=indy-mvn::${AProxDeployUrl} -DskipTests install deploy:deploy -DskipNexusStagingDeployMojo=true";
        MavenCommandLineParser lineParser = MavenCommandLineParser.build().launder(script);
        assertEquals("jaxb-ri/pom.xml", lineParser.getAlternatePomFile());
        assertNull(lineParser.getDir());
        assertEquals(
                "mvn -DskipTests=true -DskipNexusStagingDeployMojo=true -f jaxb-ri/pom.xml",
                lineParser.getRebuiltMvnCommandScript());
    }

    @Test
    void cdWithoutAlternatePomFileTest() throws IllegalArgumentException {
        String script = "cd jaxb-ri && mvn deploy -DskipTests=true";
        MavenCommandLineParser lineParser = MavenCommandLineParser.build().launder(script);
        assertEquals("jaxb-ri", lineParser.getAlternatePomFile());
        assertEquals("jaxb-ri", lineParser.getDir());
        assertEquals("mvn -DskipTests=true -f jaxb-ri", lineParser.getRebuiltMvnCommandScript());
    }

    @Test
    void cdTestWithAlternatePomFileTest() throws IllegalArgumentException {
        String script = "cd jaxb-ri && mvn -f should-override deploy -DskipTests=true";
        MavenCommandLineParser lineParser = MavenCommandLineParser.build().launder(script);
        assertEquals("should-override", lineParser.getAlternatePomFile());
        assertEquals("jaxb-ri", lineParser.getDir());
        assertEquals("mvn -DskipTests=true -f should-override", lineParser.getRebuiltMvnCommandScript());
    }

    @Test
    void quotedPropertyValueTest() throws IllegalArgumentException {
        String script = "mvn deploy -DnpmArgs=\"--strict-ssl=false --batch-mode\"";
        MavenCommandLineParser lineParser = MavenCommandLineParser.build().launder(script);
        assertEquals("mvn -DnpmArgs=\"--strict-ssl=false --batch-mode\"", lineParser.getRebuiltMvnCommandScript());
    }
}
