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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Identity.Field;
import org.cyclonedx.model.component.evidence.Method;
import org.cyclonedx.model.component.evidence.Method.Technique;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class GenericPurlWrapperUtil {

    /*
     * Help with Jackson Nothing actually uses this yet, the contents of the evidence.identity.methods.value field are
     * not well documented and not a great deal of examples See
     * https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-SBOM-en.pdf
     *
     * Taking my best guess here for something useful
     */
    @Getter
    private static class ValueChanges {
        private final String from;
        private final String to;

        public ValueChanges(String from, String to) {
            this.from = from;
            this.to = to;
        }

        public String getFrom() {
            return from;
        }

        public String getTo() {
            return to;
        }
    }

    @Getter
    private final PackageURL packageURL;

    @Getter
    private final double confidenceScore;

    private static final ObjectMapper objectMapper = new ObjectMapper();
    /*
     * Our Regex that covers most the patterns we see on the RCM release area
     */
    private static final Pattern[] FILENAME_VERSION_REGEX_STRATEGIES = {
            Pattern.compile("(?<version>\\d+\\.\\d+\\.\\d+)(?<qualsep>[.-](?<qualifier>Final|[A-Z]+\\d*))?"),
            Pattern.compile("(?<version>\\d+\\.\\d+)(?<qualsep>[.-](?<qualifier>[A-Z]+\\d*))?"),
            Pattern.compile("(?<version>\\d+_\\d+)(?<qualsep>[.-](?<qualifier>[A-Z]+\\d*))?") };

    /*
     * This is our list of PURLs we think are good examples to skew to. These are used only in the calculation of the
     * confidence score
     */
    private static final List<String> IDEAL_PURLS = Arrays.asList(
            "pkg:generic/foo-1.2.3.zip",
            "pkg:generic/foo-3.4.5-CR2.zip",
            "pkg:generic/foo-5.6.7.tar.gz",
            "pkg:generic/foo-bar-7.2.4-maven-repository.zip",
            "pkg:generic/quite-long-productname-1.2.3.DR1-maven-repository.zip",
            "pkg:generic/somepro-duct-7.4.11-runtime-maven-repository.zip");

    // We only want to run this once
    static {
        setupNorms();
    }

    // If we just want to use the class static
    public GenericPurlWrapperUtil() {
        packageURL = null;
        confidenceScore = 0.0;
    }

    public GenericPurlWrapperUtil(String purl) throws MalformedPackageURLException {
        this(new PackageURL(purl));
    }

    public GenericPurlWrapperUtil(PackageURL purl) throws MalformedPackageURLException {
        packageURL = purl;
        if (!packageURL.getType().equals(PackageURL.StandardTypes.GENERIC))
            throw new MalformedPackageURLException("Not a Generic type PURL");
        if (packageURL.getVersion() != null)
            throw new MalformedPackageURLException("PURL already has version defined");
        confidenceScore = genericPurlVersionConfidence(packageURL.canonicalize());
    }

    /*
     * Values of penalties we can tune
     */
    private static final double LENGTH_WEIGHT = 0.005;
    private static final double DIGIT_RATIO_WEIGHT = 5.0;
    private static final double LETTER_RATIO_WEIGHT = 1.5;
    private static final double SEPARATOR_RATIO_WEIGHT = 4.0;
    private static final double SEPARATOR_TYPES_WEIGHT = 0.1;
    private static final double MAX_DIGIT_RUN_WEIGHT = 0.2;
    private static final double INTERSTITIAL_LETTER_WEIGHT = 0.02;

    /*
     * Values derived one time from the "ideal" purls
     */
    private static int COUNT;
    private static double IDEAL_LENGTH;
    private static double IDEAL_DIGIT_RATIO;
    private static double IDEAL_LETTER_RATIO;
    private static double idealSeparatorRatio;
    private static double idealSeparatorTypes;
    private static double idealMaxDigitRun;
    private static double idealInterstitialLetters;

    /*
     * We should only need to get the ideal values once, not something we need to do at runtime The values above could
     * be hand jammed but easy enough to keep everything together
     */
    private static void setupNorms() {
        double totalLength = 0, totalDigitRatio = 0, totalLetterRatio = 0;
        double totalSeparatorRatio = 0, totalSeparatorTypes = 0, totalMaxDigitRun = 0;
        double totalInterstitialLetterCount = 0;

        for (String example : IDEAL_PURLS) {
            int length = example.length();
            int digitCount = 0, letterCount = 0, separatorCount = 0;
            Set<Character> separatorTypes = new HashSet<>();
            int currentDigitRun = 0, maxDigitRun = 0;

            for (char c : example.toCharArray()) {
                if (Character.isDigit(c)) {
                    digitCount++;
                    currentDigitRun++;
                } else {
                    if (currentDigitRun > maxDigitRun)
                        maxDigitRun = currentDigitRun;
                    currentDigitRun = 0;
                    if (Character.isLetter(c))
                        letterCount++;
                    else if (".-_#%:/\\".indexOf(c) != -1) {
                        separatorCount++;
                        separatorTypes.add(c);
                    }
                }
            }
            if (currentDigitRun > maxDigitRun)
                maxDigitRun = currentDigitRun;

            totalLength += length;
            totalDigitRatio += (double) digitCount / length;
            totalLetterRatio += (double) letterCount / length;
            totalSeparatorRatio += (double) separatorCount / length;
            totalSeparatorTypes += separatorTypes.size();
            totalMaxDigitRun += maxDigitRun;

            String[] parts = example.split("[.\\-_#%:/\\\\]+");
            boolean hasFoundVersionComponent = false;
            double exampleInterstitialLetters = 0;
            for (String part : parts) {
                if (part.isEmpty())
                    continue;
                boolean partHasDigit = part.matches(".*\\d.*");
                if (hasFoundVersionComponent && part.matches("[a-zA-Z]+")) {
                    exampleInterstitialLetters += part.length();
                }
                if (partHasDigit) {
                    hasFoundVersionComponent = true;
                }
            }
            totalInterstitialLetterCount += exampleInterstitialLetters;
        }

        COUNT = IDEAL_PURLS.size();
        IDEAL_LENGTH = totalLength / COUNT;
        IDEAL_DIGIT_RATIO = totalDigitRatio / COUNT;
        IDEAL_LETTER_RATIO = totalLetterRatio / COUNT;
        idealSeparatorRatio = totalSeparatorRatio / COUNT;
        idealSeparatorTypes = totalSeparatorTypes / COUNT;
        idealMaxDigitRun = totalMaxDigitRun / COUNT;
        idealInterstitialLetters = totalInterstitialLetterCount / COUNT;
    }

    /*
     * For generic purls we want to calculate our confidence in the filename method this is our confidence in the
     * likelihood of extracting the right version from a given string we apply penalties for things that is likely to
     * break the regex, such as: number of separators, variance of separators, low digit count, high digit count, letter
     * and digit ratios, these values are tuned by IDEAL_PURLs
     *
     * We will probably never hit 100% confidence as the variation of IDEAL contradict one another
     */
    public static double genericPurlVersionConfidence(String purl) {
        int purlLength = purl.length();
        int purlDigitCount = 0, purlLetterCount = 0, purlSeparatorCount = 0;
        Set<Character> purlSeparatorTypes = new HashSet<>();
        int purlCurrentDigitRun = 0, purlMaxDigitRun = 0;

        for (char c : purl.toCharArray()) {
            if (Character.isDigit(c)) {
                purlDigitCount++;
                purlCurrentDigitRun++;
            } else {
                if (purlCurrentDigitRun > purlMaxDigitRun)
                    purlMaxDigitRun = purlCurrentDigitRun;
                purlCurrentDigitRun = 0;
                if (Character.isLetter(c))
                    purlLetterCount++;
                else if (".-_#%:/\\".indexOf(c) != -1) {
                    purlSeparatorCount++;
                    purlSeparatorTypes.add(c);
                }
            }
        }
        if (purlCurrentDigitRun > purlMaxDigitRun)
            purlMaxDigitRun = purlCurrentDigitRun;

        if (purlDigitCount == 0 || purlDigitCount == purlLength || purlLetterCount == purlLength) {
            return 0.0;
        }

        double purlDigitRatio = (double) purlDigitCount / purlLength;
        double purlLetterRatio = (double) purlLetterCount / purlLength;
        double purlSeparatorRatio = (double) purlSeparatorCount / purlLength;

        double totalPenalty = 0.0;

        String[] purlParts = purl.split("[.\\-_#%:/\\\\]+");
        boolean purlHasFoundVersion = false;
        double purlInterstitialLetters = 0;
        for (String part : purlParts) {
            if (part.isEmpty())
                continue;
            boolean partHasDigit = part.matches(".*\\d.*");
            if (purlHasFoundVersion && part.matches("[a-zA-Z]+")) {
                purlInterstitialLetters += part.length();
            }
            if (partHasDigit) {
                purlHasFoundVersion = true;
            }
        }

        totalPenalty += Math.abs(purlLength - IDEAL_LENGTH) * LENGTH_WEIGHT;
        totalPenalty += Math.abs(purlDigitRatio - IDEAL_DIGIT_RATIO) * DIGIT_RATIO_WEIGHT;
        totalPenalty += Math.abs(purlLetterRatio - IDEAL_LETTER_RATIO) * LETTER_RATIO_WEIGHT;
        totalPenalty += Math.abs(purlSeparatorRatio - idealSeparatorRatio) * SEPARATOR_RATIO_WEIGHT;
        totalPenalty += Math.abs(purlSeparatorTypes.size() - idealSeparatorTypes) * SEPARATOR_TYPES_WEIGHT;
        totalPenalty += Math.abs(purlMaxDigitRun - idealMaxDigitRun) * MAX_DIGIT_RUN_WEIGHT;
        totalPenalty += Math.abs(purlInterstitialLetters - idealInterstitialLetters) * INTERSTITIAL_LETTER_WEIGHT;

        return Math.max(0.0, 1.0 - totalPenalty);
    }

    public PackageURL getVersionedPurl() {
        boolean found = false;
        PackageURL replaced = null;
        PackageURL p = this.getPackageURL();
        String fileName = p.getName();

        for (Pattern pattern : FILENAME_VERSION_REGEX_STRATEGIES) {
            Matcher matcher = pattern.matcher(fileName);
            if (matcher.find()) {
                String reconstructedVersion = matcher.group(0);
                String baseName = fileName.replace(reconstructedVersion, "")
                        .replace("--", "-")
                        .replace("..", ".")
                        .replace("-.", ".")
                        .replace("__", "_")
                        .replaceAll("^-|-$", "");

                try {

                    replaced = new PackageURL(
                            p.getType(),
                            p.getNamespace(),
                            baseName,
                            reconstructedVersion,
                            (p.getQualifiers() == null) ? null : new TreeMap<>(p.getQualifiers()),
                            p.getSubpath());
                } catch (MalformedPackageURLException e) {
                    log.error("Unable to create versioned purl from {}", p.canonicalize(), e);

                }

                found = true;
                break;
            }
        }
        if (!found) {
            log.warn("Unable to extract version from PURL: {}", p.canonicalize());
        }
        return replaced;
    }

    public Identity getAsIdentity() {
        Identity i = new Identity();
        i.setField(Field.PURL);
        i.setConcludedValue(this.getVersionedPurl().canonicalize());
        // This is hardcoded to be Filename based at the minute but we may want to add multiple methods
        Method m = new Method();
        m.setTechnique(Technique.FILENAME);
        m.setConfidence(getConfidenceScore());
        m.setValue(this.findDifferenceAsString(this.getVersionedPurl()));
        i.setMethods(List.of(m));
        i.setConfidence(i.getMethods().stream().mapToDouble(Method::getConfidence).max().orElse(0.0));
        return i;
    }

    private static Map<String, ValueChanges> findDifference(PackageURL a, PackageURL b) {
        Map<String, String> purlAMap = new HashMap<>();
        purlAMap.put("type", a.getType());
        purlAMap.put("namespace", a.getNamespace());
        purlAMap.put("name", a.getName());
        purlAMap.put("version", a.getVersion());
        purlAMap.put("subpath", a.getSubpath());
        (a.getQualifiers() != null ? a.getQualifiers() : Collections.<String, String> emptyMap())
                .forEach((k, v) -> purlAMap.put("qualifier:" + k, v));

        Map<String, String> purlBMap = new HashMap<>();
        purlBMap.put("type", b.getType());
        purlBMap.put("namespace", b.getNamespace());
        purlBMap.put("name", b.getName());
        purlBMap.put("version", b.getVersion());
        purlBMap.put("subpath", b.getSubpath());
        (b.getQualifiers() != null ? b.getQualifiers() : Collections.<String, String> emptyMap())
                .forEach((k, v) -> purlBMap.put("qualifier:" + k, v));

        Set<String> allKeys = Stream.concat(purlAMap.keySet().stream(), purlBMap.keySet().stream())
                .collect(Collectors.toSet());

        return allKeys.stream()
                .filter(key -> !Objects.equals(purlAMap.get(key), purlBMap.get(key)))
                .collect(Collectors.toMap(key -> key, key -> new ValueChanges(purlAMap.get(key), purlBMap.get(key))));
    }

    private static String findDifferenceAsString(PackageURL a, PackageURL b) {
        Map<String, ValueChanges> diff = findDifference(a, b);
        if (diff.isEmpty())
            return "";
        try {
            return objectMapper.writeValueAsString(diff);
        } catch (JsonProcessingException e) {
            log.error(
                    "Unable to deserialize differences between PURL: {} and PURL: {}",
                    a.canonicalize(),
                    b.canonicalize());
        }
        return null;
    }

    public String findDifferenceAsString(PackageURL other) {
        return findDifferenceAsString(this.getPackageURL(), other);
    }
}
