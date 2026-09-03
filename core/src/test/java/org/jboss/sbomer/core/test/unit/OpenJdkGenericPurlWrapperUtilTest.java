package org.jboss.sbomer.core.test.unit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.jboss.sbomer.core.features.sbom.utils.OpenJdkGenericPurlWrapperUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

class OpenJdkGenericPurlWrapperUtilTest {

    /**
     * Exhaustive fixture built from the full range of released OpenJDK artifact filenames. Each row is a real artifact
     * filename with the expected extracted version and the expected base name once that version is folded into the
     * PURL.
     */
    @ParameterizedTest(name = "{0} -> @{1}")
    @CsvFileSource(resources = "/openjdk-purl-versions.csv", numLinesToSkip = 1)
    @DisplayName("Should extract the full OpenJDK version for every real-world filename")
    void testVersionExtractionAgainstRealCorpus(String filename, String expectedVersion, String expectedName)
            throws MalformedPackageURLException {
        PackageURL purl = new PackageURL("generic", null, filename, null, null, null);

        assertTrue(
                OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl(purl),
                () -> "Fixture filename should be detected as OpenJDK: " + filename);

        OpenJdkGenericPurlWrapperUtil wrapper = new OpenJdkGenericPurlWrapperUtil(purl);
        PackageURL versioned = wrapper.getVersionedPurl();

        assertNotNull(versioned, () -> "Expected a versioned purl for " + filename);
        assertEquals(expectedVersion, versioned.getVersion(), () -> "version mismatch for " + filename);
        assertEquals(expectedName, versioned.getName(), () -> "name mismatch for " + filename);
    }

    @Test
    @DisplayName("Should fall back to standard version extraction for a plain semver openjdk name")
    void testFallbackToStandardVersionExtraction() throws MalformedPackageURLException {
        OpenJdkGenericPurlWrapperUtil wrapper = new OpenJdkGenericPurlWrapperUtil(
                "pkg:generic/java-openjdk-portable-1.8.0.tar.xz");
        PackageURL versionedPurl = wrapper.getVersionedPurl();

        assertNotNull(versionedPurl);
        assertEquals("1.8.0", versionedPurl.getVersion());
        assertEquals("java-openjdk-portable.tar.xz", versionedPurl.getName());
    }

    @Test
    @DisplayName("isOpenJdkPurl should match Red Hat OpenJDK and OpenJFX names")
    void testIsOpenJdkPurlMatches() {
        assertTrue(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl("java-1.8.0-openjdk-1.8.0.492.b09-1.win.x86_64.msi"));
        assertTrue(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl("java-17-openjdk-17.0.15.0.6-1.portable.jdk.tar.xz"));
        assertTrue(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl("openjdk-11.0.22-1-provenance-and-verification.zip"));
        assertTrue(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl("openjfx-8.0.171-1.b11.redhat.windows.x86.zip"));
    }

    @Test
    @DisplayName("isOpenJdkPurl should not match non-openjdk names or Temurin builds")
    void testIsOpenJdkPurlDoesNotMatch() {
        assertFalse(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl("my-product-1.2.3.zip"));
        // Temurin/Adoptium is intentionally out of scope (case-sensitive, no java-*-openjdk prefix)
        assertFalse(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl("OpenJDK25U-jdk_x64_windows_hotspot_25.0.2_10.zip"));
        assertFalse(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl((String) null));
    }

    @Test
    @DisplayName("isOpenJdkPurl should require a generic type PackageURL")
    void testIsOpenJdkPurlWithPackageURL() throws MalformedPackageURLException {
        assertTrue(
                OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl(
                        new PackageURL("pkg:generic/java-1.8.0-openjdk-1.8.0.492.b09-1.win.x86_64.msi")));
        assertFalse(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl(new PackageURL("pkg:maven/foo/java-11-openjdk@1.0")));
        assertFalse(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl((PackageURL) null));
    }
}
