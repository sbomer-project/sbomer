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
package org.jboss.sbomer.core.features.sbom.utils;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EnvironmentAttributesUtils {

    private EnvironmentAttributesUtils() {
        // This is a utility class
    }

    /**
     * Mapping of Gradle versions from PNC to SDKMAN-compliant versions. PNC may provide incomplete version strings
     * (e.g., "9") that need to be expanded to valid SDKMAN versions.
     *
     * For single-digit major versions, we map to the highest available X.0.Y patch version for that major version in
     * SDKMAN (e.g., "9" -> "9.0.0", "8" -> "8.0.2").
     *
     * Add more mappings as needed when we get a mismatch
     */
    private static final Map<String, String> GRADLE_VERSION_OVERRIDES = Map.of(
            "9",
            "9.0.0", // Highest 9.0.x available in SDKMAN
            "8",
            "8.0.2" // Highest 8.0.x available in SDKMAN
    );

    private static final String SBT_ATTRIBUTE_KEY = "SBT";
    private static final String MAVEN_ATTRIBUTE_KEY = "MAVEN";
    private static final String GRADLE_ATTRIBUTE_KEY = "GRADLE";
    private static final String JDK_ATTRIBUTE_KEY = "JDK";
    private static final String NODEJS_ATTRIBUTE_KEY = "NODEJS";

    private static final String SBT_SDKMAN_KEY = "sbt";
    private static final String MAVEN_SDKMAN_KEY = "maven";
    private static final String GRADLE_SDKMAN_KEY = "gradle";
    private static final String SDK_SDKMAN_KEY = "java";
    private static final String NODEJS_NVM_KEY = "node";

    private static final String JAVA_LEGACY_VERSION_REGEX = "^1\\.(\\d+)";
    private static final String JAVA_VERSION_REGEX = "^([^.-]+)";
    private static final String GRADLE_MAJOR_VERSION_REGEX = "^(\\d+)";

    private static final Pattern JAVA_LEGACY_VERSION_PATTERN = Pattern.compile(JAVA_LEGACY_VERSION_REGEX);
    private static final Pattern JAVA_VERSION_PATTERN = Pattern.compile(JAVA_VERSION_REGEX);
    private static final Pattern GRADLE_MAJOR_VERSION_PATTERN = Pattern.compile(GRADLE_MAJOR_VERSION_REGEX);

    public static Map<String, String> getSDKManCompliantAttributes(Map<String, String> environmentAttributes) {
        Map<String, String> sdkManAttributes = new HashMap<>();

        // Find Maven
        Optional<String> mavenVersion = getMavenSDKManCompliantVersion(environmentAttributes);
        mavenVersion.ifPresent(s -> sdkManAttributes.put(MAVEN_SDKMAN_KEY, s.trim()));

        // Find Gradle
        Optional<String> gradleVersion = getGradleSDKManCompliantVersion(environmentAttributes);
        gradleVersion.ifPresent(s -> sdkManAttributes.put(GRADLE_SDKMAN_KEY, s.trim()));

        // Find Java. We need to do some ugly polishing due to the metadata available in PNC.
        Optional<String> javaVersion = getJavaSDKManCompliantVersion(environmentAttributes);
        javaVersion.ifPresent(s -> sdkManAttributes.put(SDK_SDKMAN_KEY, s.trim()));

        // Find SBT
        Optional<String> sbtVersion = getSbtSDKManCompliantVersion(environmentAttributes);
        sbtVersion.ifPresent(s -> sdkManAttributes.put(SBT_SDKMAN_KEY, s.trim()));
        return sdkManAttributes;
    }

    public static Optional<String> getMavenSDKManCompliantVersion(Map<String, String> environmentAttributes) {
        if (environmentAttributes == null || environmentAttributes.isEmpty()) {
            return Optional.empty();
        }

        return environmentAttributes.entrySet()
                .stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase(MAVEN_ATTRIBUTE_KEY))
                .map(Map.Entry::getValue)
                .findFirst();
    }

    public static Optional<String> getGradleSDKManCompliantVersion(Map<String, String> environmentAttributes) {
        if (environmentAttributes == null || environmentAttributes.isEmpty()) {
            return Optional.empty();
        }

        Optional<String> gradleVersion = environmentAttributes.entrySet()
                .stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase(GRADLE_ATTRIBUTE_KEY))
                .map(Map.Entry::getValue)
                .findFirst();

        if (gradleVersion.isPresent()) {
            String version = gradleVersion.get().trim();
            // Apply version override mapping if available (e.g., "9" -> "9.0.0")
            return Optional.of(GRADLE_VERSION_OVERRIDES.getOrDefault(version, version));
        }

        return Optional.empty();
    }

    public static Optional<String> getJavaSDKManCompliantVersion(Map<String, String> environmentAttributes) {
        if (environmentAttributes == null || environmentAttributes.isEmpty()) {
            return Optional.empty();
        }

        Optional<String> javaVersion = environmentAttributes.entrySet()
                .stream()
                .filter(entry -> entry.getKey().contains(JDK_ATTRIBUTE_KEY) && !entry.getValue().contains("Mandrel"))
                .map(
                        entry -> entry.getValue()
                                .replace("OpenJDK", "")
                                .replace("OracleJDK", "")
                                .replace("Oracle JDK", ""))
                .findFirst();

        if (javaVersion.isPresent()) {
            String javaVersionString = javaVersion.get().trim();
            if (javaVersionString.startsWith("1.")) {
                Matcher matcher = JAVA_LEGACY_VERSION_PATTERN.matcher(javaVersionString);
                if (matcher.find()) {
                    return Optional.of(matcher.group(1));
                }
            } else if (javaVersionString.startsWith("8u")) {
                return Optional.of("8");
            } else {
                Matcher matcher = JAVA_VERSION_PATTERN.matcher(javaVersionString);
                if (matcher.find()) {
                    return Optional.of(matcher.group(1));
                }
            }
        }
        return Optional.empty();
    }

    public static Optional<String> getNodeJsNvmCompliantVersion(Map<String, String> environmentAttributes) {
        if (environmentAttributes == null || environmentAttributes.isEmpty()) {
            return Optional.empty();
        }

        return environmentAttributes.entrySet()
                .stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase(NODEJS_ATTRIBUTE_KEY))
                .map(Map.Entry::getValue)
                .findFirst();
    }

    public static Optional<String> getSbtSDKManCompliantVersion(Map<String, String> environmentAttributes) {
        if (environmentAttributes == null || environmentAttributes.isEmpty()) {
            return Optional.empty();
        }

        return environmentAttributes.entrySet()
                .stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase(SBT_ATTRIBUTE_KEY))
                .map(Map.Entry::getValue)
                .findFirst();
    }

    public static Optional<String> getGradleSDKManCompliantMajorVersion(Map<String, String> environmentAttributes) {
        Optional<String> gradleVersion = getGradleSDKManCompliantVersion(environmentAttributes);
        if (gradleVersion.isPresent()) {
            Matcher matcher = GRADLE_MAJOR_VERSION_PATTERN.matcher(gradleVersion.get().trim());
            if (matcher.find()) {
                return Optional.of(matcher.group(1));
            }
        }
        return Optional.empty();
    }

    public static Map<String, String> getNvmCompliantAttributes(Map<String, String> environmentAttributes) {
        Map<String, String> nvmAttributes = new HashMap<>();

        // Find Node.js
        Optional<String> nodeJSVersion = getNodeJsNvmCompliantVersion(environmentAttributes);
        nodeJSVersion.ifPresent(s -> nvmAttributes.put(NODEJS_NVM_KEY, s.trim()));

        return nvmAttributes;
    }

}
