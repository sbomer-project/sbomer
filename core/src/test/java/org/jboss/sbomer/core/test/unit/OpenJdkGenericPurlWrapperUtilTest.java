package org.jboss.sbomer.core.test.unit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.jboss.sbomer.core.features.sbom.utils.OpenJdkGenericPurlWrapperUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

class OpenJdkGenericPurlWrapperUtilTest {

    @Test
    @DisplayName("Should extract JDK 8 build version from portable JDK filename")
    void testVersionExtractionJdk8PortableJdk() throws MalformedPackageURLException {
        OpenJdkGenericPurlWrapperUtil wrapper = new OpenJdkGenericPurlWrapperUtil(
                "pkg:generic/java-openjdk-portable-1.8.0.492.b09-1.portable.jdk.el.x86_64.tar.xz");
        PackageURL versionedPurl = wrapper.getVersionedPurl();

        assertNotNull(versionedPurl);
        assertEquals("1.8.0.492.b09-1", versionedPurl.getVersion());
        assertEquals("java-openjdk-portable.portable.jdk.el.x86_64.tar.xz", versionedPurl.getName());
    }

    @Test
    @DisplayName("Should extract JDK 8 build version from portable JRE filename")
    void testVersionExtractionJdk8PortableJre() throws MalformedPackageURLException {
        OpenJdkGenericPurlWrapperUtil wrapper = new OpenJdkGenericPurlWrapperUtil(
                "pkg:generic/java-openjdk-portable-1.8.0.492.b09-1.portable.jre.el.x86_64.tar.xz");
        PackageURL versionedPurl = wrapper.getVersionedPurl();

        assertNotNull(versionedPurl);
        assertEquals("1.8.0.492.b09-1", versionedPurl.getVersion());
        assertEquals("java-openjdk-portable.portable.jre.el.x86_64.tar.xz", versionedPurl.getName());
    }

    @Test
    @DisplayName("Should extract JDK 8 build version from portable debuginfo filename")
    void testVersionExtractionJdk8PortableDebuginfo() throws MalformedPackageURLException {
        OpenJdkGenericPurlWrapperUtil wrapper = new OpenJdkGenericPurlWrapperUtil(
                "pkg:generic/java-openjdk-portable-1.8.0.492.b09-1.portable.debuginfo.jdk.el.x86_64.tar.xz");
        PackageURL versionedPurl = wrapper.getVersionedPurl();

        assertNotNull(versionedPurl);
        assertEquals("1.8.0.492.b09-1", versionedPurl.getVersion());
        assertEquals("java-openjdk-portable.portable.debuginfo.jdk.el.x86_64.tar.xz", versionedPurl.getName());
    }

    @Test
    @DisplayName("Should fall back to standard version extraction for non-JDK-build filenames")
    void testFallbackToStandardVersionExtraction() throws MalformedPackageURLException {
        OpenJdkGenericPurlWrapperUtil wrapper = new OpenJdkGenericPurlWrapperUtil(
                "pkg:generic/java-openjdk-portable-1.8.0.tar.xz");
        PackageURL versionedPurl = wrapper.getVersionedPurl();

        assertNotNull(versionedPurl);
        assertEquals("1.8.0", versionedPurl.getVersion());
        assertEquals("java-openjdk-portable.tar.xz", versionedPurl.getName());
    }

    @Test
    @DisplayName("isOpenJdkPurl should match java-openjdk names")
    void testIsOpenJdkPurlMatchesJavaOpenjdk() {
        assertTrue(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl("java-openjdk-portable-1.8.0.tar.xz"));
        assertTrue(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl("java-11-openjdk-11.0.25.tar.xz"));
        assertTrue(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl("java-17-openjdk-17.0.20.0.8-1.win.jdk.x86_64.msi"));
    }

    @Test
    @DisplayName("isOpenJdkPurl should not match non-openjdk names")
    void testIsOpenJdkPurlDoesNotMatchOther() {
        assertFalse(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl("my-product-1.2.3.zip"));
        assertFalse(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl("openjdk-wrapper-1.0.tar.gz"));
        assertFalse(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl((String) null));
    }

    @Test
    @DisplayName("isOpenJdkPurl should work with PackageURL objects")
    void testIsOpenJdkPurlWithPackageURL() throws MalformedPackageURLException {
        assertTrue(
                OpenJdkGenericPurlWrapperUtil
                        .isOpenJdkPurl(new PackageURL("pkg:generic/java-openjdk-portable-1.8.0.492.b09-1.tar.xz")));
        assertFalse(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl(new PackageURL("pkg:generic/my-product-1.2.3.zip")));
        assertFalse(OpenJdkGenericPurlWrapperUtil.isOpenJdkPurl((PackageURL) null));
    }
}
