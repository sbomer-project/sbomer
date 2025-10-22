package org.jboss.sbomer.core.test.unit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Method;
import org.cyclonedx.model.component.evidence.Method.Technique;
import org.jboss.sbomer.core.features.sbom.utils.GenericPurlWrapperUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

class GenericPurlWrapperUtilTest {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    private static class Diff {
        public String from;
        public String to;

        // A no-arg constructor is also needed by Jackson for deserialization
        public Diff() {
        }

        public String getFrom() {
            return from;
        }

        public String getTo() {
            return to;
        }
    }

    @Test
    @DisplayName("Constructor should succeed for a valid versionless generic PURL")
    void testConstructorWithValidGenericPurlSucceeds() throws MalformedPackageURLException {
        String purlStr = "pkg:generic/my-component-name";
        GenericPurlWrapperUtil wrapper = new GenericPurlWrapperUtil(purlStr);

        assertNotNull(wrapper.getPackageURL());
        assertEquals(purlStr, wrapper.getPackageURL().canonicalize());
        assertTrue(wrapper.getConfidenceScore() > -1, "Confidence score should be calculated");
    }

    @Test
    @DisplayName("Constructor should throw exception for a non-generic PURL")
    void testConstructorWithNonGenericPurlThrowsException() {
        String purlStr = "pkg:maven/org.jboss/sbomer@1.0.0";
        MalformedPackageURLException ex = assertThrows(
                MalformedPackageURLException.class,
                () -> new GenericPurlWrapperUtil(purlStr));
        assertEquals("Not a Generic type PURL", ex.getMessage());
    }

    @Test
    @DisplayName("Constructor should throw exception for a PURL that already has a version")
    void testConstructorWithVersionedPurlThrowsException() {
        String purlStr = "pkg:generic/my-component@1.2.3";
        MalformedPackageURLException ex = assertThrows(
                MalformedPackageURLException.class,
                () -> new GenericPurlWrapperUtil(purlStr));
        assertEquals("PURL already has version defined", ex.getMessage());
    }

    @Test
    @DisplayName("Confidence score should be high for an ideal-looking PURL")
    void testConfidenceIdealPurlReturnsHighScore() {
        double score = GenericPurlWrapperUtil.genericPurlVersionConfidence("pkg:generic/product-1.2.3-artifact.zip");
        assertTrue(score > 0.6, "Score for an ideal PURL should be very high");
    }

    @Test
    @DisplayName("Confidence score should be 0.0 for a PURL with only letters")
    void testConfidenceAllLettersReturnsZero() {
        double score = GenericPurlWrapperUtil.genericPurlVersionConfidence("pkg:generic/alllettersinname");
        assertEquals(0.0, score, "Score for a PURL with no digits should be zero");
    }

    @Test
    @DisplayName("Confidence score should be 0.0 for a PURL with only digits")
    void testConfidenceAllDigitsReturnsZero() {
        double score = GenericPurlWrapperUtil.genericPurlVersionConfidence("pkg:generic/1234567890");
        assertEquals(0.0, score, "Score for a PURL with no letters should be zero");
    }

    @Test
    @DisplayName("Should extract standard X.Y.Z version correctly")
    void testVersionExtractionStandardVersion() throws MalformedPackageURLException {
        GenericPurlWrapperUtil wrapper = new GenericPurlWrapperUtil("pkg:generic/my-product-1.2.3.zip");
        PackageURL versionedPurl = wrapper.getVersionedPurl();

        assertNotNull(versionedPurl);
        assertEquals("my-product.zip", versionedPurl.getName());
        assertEquals("1.2.3", versionedPurl.getVersion());
    }

    @Test
    @DisplayName("Should extract version with a qualifier (e.g., -CR2)")
    void testVersionExtractionVersionWithQualifier() throws MalformedPackageURLException {
        GenericPurlWrapperUtil wrapper = new GenericPurlWrapperUtil("pkg:generic/another-product-5.6.7-CR2.tar.gz");
        PackageURL versionedPurl = wrapper.getVersionedPurl();

        assertNotNull(versionedPurl);
        assertEquals("another-product.tar.gz", versionedPurl.getName());
        assertEquals("5.6.7-CR2", versionedPurl.getVersion());
    }

    @Test
    @DisplayName("Should extract X.Y version correctly")
    void testVersionExtractionTwoPartVersion() throws MalformedPackageURLException {
        GenericPurlWrapperUtil wrapper = new GenericPurlWrapperUtil("pkg:generic/lib-name-8.9-final-dist");
        PackageURL versionedPurl = wrapper.getVersionedPurl();

        assertNotNull(versionedPurl);
        assertEquals("lib-name-final-dist", versionedPurl.getName());
        assertEquals("8.9", versionedPurl.getVersion());
    }

    @Test
    @DisplayName("Should extract X_Y version correctly")
    void testVersionExtractionUnderscoreVersion() throws MalformedPackageURLException {
        GenericPurlWrapperUtil wrapper = new GenericPurlWrapperUtil("pkg:generic/archive_10_11_final");
        PackageURL versionedPurl = wrapper.getVersionedPurl();

        assertNotNull(versionedPurl);
        assertEquals("archive_final", versionedPurl.getName());
        assertEquals("10_11", versionedPurl.getVersion());
    }

    @Test
    @DisplayName("Should preserve namespace, qualifiers, and subpath after version extraction")
    void testVersionExtractionPreservesOtherPurlParts() throws MalformedPackageURLException {
        String purlStr = "pkg:generic/redhat/foo-runner-1.13.7.Final.zip?download_url=http://foo.bar&type=zip#lib/main.jar";
        GenericPurlWrapperUtil wrapper = new GenericPurlWrapperUtil(purlStr);
        PackageURL versionedPurl = wrapper.getVersionedPurl();

        assertNotNull(versionedPurl);
        assertEquals("redhat", versionedPurl.getNamespace());
        assertEquals("foo-runner.zip", versionedPurl.getName());
        assertEquals("1.13.7.Final", versionedPurl.getVersion());
        assertEquals("zip", versionedPurl.getQualifiers().get("type"));
        assertEquals("http://foo.bar", versionedPurl.getQualifiers().get("download_url"));
        assertEquals("lib/main.jar", versionedPurl.getSubpath());
    }

    @Test
    @DisplayName("Should return null if no version can be extracted")
    void testVersionExtractionNoVersionFoundReturnsNull() throws MalformedPackageURLException {
        GenericPurlWrapperUtil wrapper = new GenericPurlWrapperUtil("pkg:generic/product-without-version");
        PackageURL versionedPurl = wrapper.getVersionedPurl();

        assertNull(versionedPurl);
    }

    @Test
    @DisplayName("Should create a valid Identity object")
    void testGetAsIdentityCreatesCorrectIdentity() throws MalformedPackageURLException {
        GenericPurlWrapperUtil wrapper = new GenericPurlWrapperUtil("pkg:generic/identity-test-4.5.6");
        Identity identity = wrapper.getAsIdentity();

        assertNotNull(identity);
        assertEquals(Identity.Field.PURL, identity.getField());
        assertEquals("pkg:generic/identity-test@4.5.6", identity.getConcludedValue());
        assertEquals(wrapper.getConfidenceScore(), identity.getConfidence());

        List<Method> methods = identity.getMethods();
        assertNotNull(methods);
        assertEquals(1, methods.size());

        Method method = methods.get(0);
        assertEquals(Technique.FILENAME, method.getTechnique());
        assertEquals(wrapper.getConfidenceScore(), method.getConfidence());
        assertTrue(method.getValue().contains("\"version\":{\"from\":null,\"to\":\"4.5.6\"}"));
    }

    @Test
    @DisplayName("findDifference should identify version and name changes")
    void testFindDifferenceIdentifiesChanges()
            throws MalformedPackageURLException, JsonMappingException, JsonProcessingException {
        GenericPurlWrapperUtil wrapper = new GenericPurlWrapperUtil("pkg:generic/my-lib-1.0.0");
        PackageURL versionedPurl = wrapper.getVersionedPurl();
        String diff = wrapper.findDifferenceAsString(versionedPurl);
        Map<String, Diff> diffMap = objectMapper.readValue(diff, new TypeReference<>() {
        });
        assertEquals(2, diffMap.size());
        assertEquals(diffMap.keySet(), Set.of("name", "version"));
        assertEquals(
                "{\"name\":{\"from\":\"my-lib-1.0.0\",\"to\":\"my-lib\"},\"version\":{\"from\":null,\"to\":\"1.0.0\"}}",
                diff);
    }

    @Test
    @DisplayName("findDifference should return an empty map for identical PURLs")
    void testFindDifferenceIdenticalPurlsReturnsEmptyMap() throws MalformedPackageURLException {
        GenericPurlWrapperUtil wrapper = new GenericPurlWrapperUtil("pkg:generic/no-change");
        String diff = wrapper.findDifferenceAsString(wrapper.getPackageURL());

        assertEquals("", diff);
    }
}
