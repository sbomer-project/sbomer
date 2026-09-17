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

import java.util.Objects;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

import lombok.extern.slf4j.Slf4j;

/**
 * OpenJDK/OpenFX generic PURLs carry a richer version than a plain semver: they append a build number and release (e.g.
 * {@code 1.8.0.492.b09-1}) and, for newer feature releases, a four or five part version plus release (e.g.
 * {@code 17.0.15.0.6-1}). The generic {@link GenericPurlWrapperUtil} strategies only extract the leading semver and
 * strand the remainder in the name, so this subclass extracts the full version instead.
 *
 * <p>
 * Two types of filenames are handled:
 * <ul>
 * <li>Red Hat OpenJDK/OpenJFX, where the version is the leading run of numeric/{@code bNN} build tokens that follows
 * the {@code openjdk-}/{@code openjfx-} marker (skipping intervening words such as {@code -portable-}, {@code -jre-},
 * {@code -debug-}, {@code -static-devel-}), optionally reaching through a trailing {@code -redhat.bNN} qualifier used
 * by some older Windows builds.</li>
 * <li>Eclipse Temurin/Adoptium, where the version is the trailing {@code _<version>} run before the file extension such
 * as {@code 25.0.3_9}, {@code 25.0.4.1_1}, {@code 25_36}.</li>
 * </ul>
 */
@Slf4j
public class OpenJdkGenericPurlWrapperUtil extends GenericPurlWrapperUtil {

    /**
     * Matches Red Hat OpenJDK and OpenJFX filenames. Case-sensitive. Temurin/Adoptium filenames are matched separately
     * by {@link #TEMURIN_NAME_PATTERN}.
     */
    private static final Pattern OPENJDK_NAME_PATTERN = Pattern
            .compile("^(?:java-.*-openjdk|java-openjdk|openjdk-|openjfx)");

    /**
     * Captures the version run after the {@code openjdk}/{@code openjfx} marker. {@code [a-z-]*?} lazily skips
     * intervening classifier words; the version is a run of numeric or {@code bNN} tokens separated by {@code . - _},
     * optionally extended through a trailing {@code -redhat.bNN} build qualifier.
     */
    private static final Pattern OPENJDK_VERSION_PATTERN = Pattern
            .compile("open(?:jdk|jfx)[a-z-]*?-(?<version>(?:\\d+|b\\d+)(?:[._-](?:\\d+|b\\d+))*(?:-redhat\\.b\\d+)?)");

    /**
     * Matches Eclipse Temurin/Adoptium filenames where the {@code OpenJDK&lt;major&gt;U-} prefix carries the major
     * version ({@code OpenJDK25U-...}, {@code OpenJDK26U-...}).
     */
    private static final Pattern TEMURIN_NAME_PATTERN = Pattern.compile("^OpenJDK\\d+U-");

    /**
     * Decomposes a Temurin/Adoptium filename into three named groups:
     * <ul>
     * <li>{@code name}: the file prefix (everything before the {@code _<version>}</li>
     * <li>{@code version}: the version run (a numerical sequence with delimiters {@code [._-]})</li>
     * <li>{@code ext}: the extension ({@code .msi}, {@code .zip})</li>
     * </ul>
     */
    private static final Pattern TEMURIN_FILENAME_PATTERN = Pattern
            .compile("^(?<name>OpenJDK\\d+U-.*?)_(?<version>\\d+(?:[._-]\\d+)*(?:-[A-Za-z]+)?)(?<ext>\\.[A-Za-z].*)?$");

    public OpenJdkGenericPurlWrapperUtil(String purl) throws MalformedPackageURLException {
        super(purl);
    }

    public OpenJdkGenericPurlWrapperUtil(PackageURL purl) throws MalformedPackageURLException {
        super(purl);
    }

    @Override
    public PackageURL getVersionedPurl() {
        PackageURL p = this.getPackageURL();
        String fileName = p.getName();

        // Temurin/Adoptium: compose the base name directly
        Matcher temurinMatcher = TEMURIN_FILENAME_PATTERN.matcher(fileName);
        if (temurinMatcher.find()) {
            String baseName = temurinMatcher.group("name")
                    + Objects.requireNonNullElse(temurinMatcher.group("ext"), "");
            return getVersionedPurl(p, baseName, temurinMatcher.group("version"));
        }

        // Red Hat OpenJDK/OpenJFX: the version follows the openjdk/openjfx marker; strip it back out of the name.
        Matcher openJdkMatcher = OPENJDK_VERSION_PATTERN.matcher(fileName);
        if (openJdkMatcher.find()) {
            String baseName = stripVersionFromName(
                    fileName,
                    openJdkMatcher.start("version"),
                    openJdkMatcher.end("version"));
            return getVersionedPurl(p, baseName, openJdkMatcher.group("version"));
        }

        // Fall back to the generic strategies (e.g. plain semver names)
        return super.getVersionedPurl();
    }

    private PackageURL getVersionedPurl(PackageURL p, String baseName, String version) {
        try {
            return new PackageURL(
                    p.getType(),
                    p.getNamespace(),
                    baseName,
                    version,
                    (p.getQualifiers() == null) ? null : new TreeMap<>(p.getQualifiers()),
                    p.getSubpath());
        } catch (MalformedPackageURLException e) {
            log.error("Unable to create versioned purl from {}", p.canonicalize(), e);
            return null;
        }
    }

    public static boolean isOpenJdkPurl(PackageURL purl) {
        return purl != null && "generic".equals(purl.getType()) && isOpenJdkPurl(purl.getName());
    }

    public static boolean isOpenJdkPurl(String purlName) {
        return purlName != null
                && (OPENJDK_NAME_PATTERN.matcher(purlName).find() || TEMURIN_NAME_PATTERN.matcher(purlName).find());
    }
}
