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
package org.jboss.sbomer.core.features.sbom.utils.commandline.maven;

import static org.jboss.sbomer.core.features.sbom.utils.commandline.maven.MavenCommandOptions.ALTERNATE_POM;
import static org.jboss.sbomer.core.features.sbom.utils.commandline.maven.MavenCommandOptions.PROFILES_OPTION;
import static org.jboss.sbomer.core.features.sbom.utils.commandline.maven.MavenCommandOptions.PROJECTS_OPTION;
import static org.jboss.sbomer.core.features.sbom.utils.commandline.maven.MavenCommandOptions.SYSTEM_PROPERTIES_OPTION;
import static org.jboss.sbomer.core.features.sbom.utils.commandline.maven.MavenCommandOptions.addAlternatePomOption;
import static org.jboss.sbomer.core.features.sbom.utils.commandline.maven.MavenCommandOptions.addIgnorableOptions;
import static org.jboss.sbomer.core.features.sbom.utils.commandline.maven.MavenCommandOptions.addIneffectiveOptions;
import static org.jboss.sbomer.core.features.sbom.utils.commandline.maven.MavenCommandOptions.addNoArgsOptions;
import static org.jboss.sbomer.core.features.sbom.utils.commandline.maven.MavenCommandOptions.addProfilesOptions;
import static org.jboss.sbomer.core.features.sbom.utils.commandline.maven.MavenCommandOptions.addProjectsOptions;
import static org.jboss.sbomer.core.features.sbom.utils.commandline.maven.MavenCommandOptions.addSystemPropertyOptions;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.codehaus.plexus.util.FileUtils;
import org.codehaus.plexus.util.StringUtils;
import org.codehaus.plexus.util.cli.CommandLineUtils;

import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

@Getter
@Slf4j
@ToString
public class MavenCommandLineParser {

    public static final String SPLIT_BY_SPACE_HONORING_SINGLE_AND_DOUBLE_QUOTES = "\\s+(?=(?:[^'\"]*['\"][^'\"]*['\"])*[^'\"]*$)"; // NOSONAR
                                                                                                                                   // We
                                                                                                                                   // do
                                                                                                                                   // not
                                                                                                                                   // expect
                                                                                                                                   // large
                                                                                                                                   // inputs

    private static final String MVN = "mvn";

    private static final String MVNW = "mvnw";

    private static final Pattern SEPARATOR_PATTERN = Pattern.compile(";|&&|\\|\\||\\r?\\n");

    private static final Pattern CD_PATTERN = Pattern.compile("^cd\\s+(\\S+)");

    @ToString.Exclude
    private final CommandLineParser parser;

    @ToString.Exclude
    private final Options cmdOptions;

    private List<String> profiles;
    private Properties properties;
    private List<String> options;
    private List<String> projects;
    private List<String> noArgsOptions;
    private String alternatePomFile;
    private String dir;
    private String fullCommandScript = "";
    private String extractedMvnCommandScript = "";
    private String rebuiltMvnCommandScript = "";

    public static MavenCommandLineParser build() {
        return new MavenCommandLineParser();
    }

    private MavenCommandLineParser() {
        parser = new DefaultParser();
        cmdOptions = createOptions();
        reset();
    }

    private Options createOptions() {
        Options localOptions = new Options();

        addIgnorableOptions(localOptions);
        addIneffectiveOptions(localOptions);
        addNoArgsOptions(localOptions);
        addSystemPropertyOptions(localOptions);
        addProfilesOptions(localOptions);
        addProjectsOptions(localOptions);
        addAlternatePomOption(localOptions);

        return localOptions;
    }

    private void reset() {
        fullCommandScript = "";
        extractedMvnCommandScript = "";
        rebuiltMvnCommandScript = "";
        profiles = new ArrayList<>();
        properties = new Properties();
        options = new ArrayList<>();
        projects = new ArrayList<>();
        noArgsOptions = new ArrayList<>();
        alternatePomFile = null;
        dir = null;
    }

    public MavenCommandLineParser launder(String fullCmdScript) {
        log.info("Laundering provided Maven command script '{}'", fullCmdScript);
        reset();

        try {
            fullCommandScript = fullCmdScript;
            extractedMvnCommandScript = extractMavenCommand(fullCommandScript);
            String[] tokens = CommandLineUtils.translateCommandline(extractedMvnCommandScript);
            CommandLine cmd = parser.parse(cmdOptions, tokens);

            if (cmd.hasOption(PROFILES_OPTION)) {
                profiles = parseCommaSeparatedValues(cmd.getOptionValues(PROFILES_OPTION));
            }

            if (cmd.hasOption(SYSTEM_PROPERTIES_OPTION)) {
                properties = getOptionPropertiesWithConcatenation(cmd, SYSTEM_PROPERTIES_OPTION);
            }

            if (cmd.hasOption(PROJECTS_OPTION)) {
                projects = parseKeyValuePairs(cmd.getOptionValues(PROJECTS_OPTION));
            }

            if (cmd.hasOption(ALTERNATE_POM)) {
                alternatePomFile = cmd.getOptionValue(ALTERNATE_POM);
            } else if (dir != null) {
                alternatePomFile = dir;
            }

            for (String option : MavenCommandOptions.NO_ARGS_OPTIONS) {
                if (cmd.hasOption(option)) {
                    noArgsOptions.add(option);
                }
            }

            options = cmd.getArgList();
            rebuiltMvnCommandScript = rebuildMavenCommand();
        } catch (ParseException e) {
            throw new IllegalArgumentException("Provided build script contains unknown values", e);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to translate commandline", e);
        }

        return this;
    }

    private String extractMavenCommand(String fullScript) {
        log.info("Extracting Maven command from full script '{}'", fullScript);
        String extractedMavenCommand = "";
        String cd = null;
        String lastCd = null;
        String[] segments = SEPARATOR_PATTERN.split(fullScript);

        for (String segment : segments) {
            String trimmedSegment = segment.trim();

            if (trimmedSegment.isEmpty()) {
                continue;
            }

            if (isMvn(trimmedSegment)) {
                extractedMavenCommand = trimmedSegment;
                cd = lastCd;
            } else {
                Matcher cdMatcher = CD_PATTERN.matcher(trimmedSegment);

                if (cdMatcher.find()) {
                    lastCd = cdMatcher.group(1);
                }
            }
        }

        dir = cd;
        log.info("Extracted Maven command '{}' (working directory: '{}')", extractedMavenCommand, dir);
        return extractedMavenCommand;
    }

    private static boolean isMvn(String tokens) {
        int end = 0;

        while (true) {
            int length = tokens.length();

            if (end >= length || Character.isWhitespace(tokens.charAt(end))) {
                break;
            }

            end++;
        }

        String firstToken = tokens.substring(0, end);
        String filename = FileUtils.filename(firstToken);
        String basename = FileUtils.removeExtension(filename);
        String basenameLowerCase = basename.toLowerCase(Locale.ROOT);
        return (MVN.equals(basenameLowerCase) || MVNW.equals(basenameLowerCase));
    }

    private String rebuildMavenCommand() {
        return "mvn" + rebuildNoArgsCmd() + rebuildProfilesCmd() + rebuildProjectsCmd() + rebuildSystemPropertiesCmd()
                + rebuildAlternatePomFileCmd();
    }

    private String rebuildProfilesCmd() {
        if (profiles.isEmpty()) {
            return "";
        }
        return " -" + PROFILES_OPTION + String.join(",", profiles);
    }

    private String rebuildProjectsCmd() {
        if (projects.isEmpty()) {
            return "";
        }

        String projectList = String.join(",", projects);
        // Remove single and double quotes if the string starts and ends with them
        projectList = projectList.replaceAll("(^['\"])|(['\"]$)", "").trim();
        // Finally, remove all spaces inside the string
        projectList = projectList.replaceAll("\\s+", "");

        return " -" + PROJECTS_OPTION + " " + projectList;
    }

    private String rebuildAlternatePomFileCmd() {
        if (alternatePomFile == null) {
            return "";
        }

        return " -" + ALTERNATE_POM + " " + alternatePomFile;
    }

    private String rebuildNoArgsCmd() {
        if (noArgsOptions.isEmpty()) {
            return "";
        }
        return " -" + String.join(" -", noArgsOptions);
    }

    private String rebuildSystemPropertiesCmd() {
        if (properties.isEmpty()) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        properties.forEach((key, value) -> {
            String s = String.valueOf(value);

            if (StringUtils.contains(s, ' ') && !isQuoted(s)) {
                s = quote(s);
            }

            sb.append(" -").append(SYSTEM_PROPERTIES_OPTION).append(key).append("=").append(s);
        });
        return sb.toString();
    }

    private static String quote(String s) {
        return "\"" + s + "\"";
    }

    private static boolean isQuoted(String s) {
        return (s.startsWith("\"") && s.endsWith("\""));
    }

    /*
     * Enhance the getOptionProperties to concatenate all value tokens after the key token
     */
    private Properties getOptionPropertiesWithConcatenation(CommandLine cmd, String opt) {
        Properties props = new Properties();

        for (Option option : cmd.getOptions()) {
            if (opt.equals(option.getOpt()) || opt.equals(option.getLongOpt())) {
                List<String> values = option.getValuesList();

                if (values.size() > 2) {
                    // Concatenate all values except the first one
                    String concatenatedValues = values.stream()
                            .skip(1)
                            .collect(Collectors.joining(String.valueOf(option.getValueSeparator())));

                    // Trim surrounding quotes, filter out tokens containing '$', and re-add quotes if needed
                    concatenatedValues = trimAndFilterValues(concatenatedValues);
                    if (concatenatedValues.isEmpty())
                        continue;

                    props.put(values.get(0), concatenatedValues);
                } else if (values.size() == 2) {
                    // Only include if the second value does not contain '$'
                    if (!values.get(1).contains("$")) {
                        props.put(values.get(0), values.get(1));
                    }
                } else if (values.size() == 1) {
                    // Treat single value as a boolean flag
                    props.put(values.get(0), "true");
                }
            }
        }

        return props;
    }

    private String trimAndFilterValues(String concatenatedValues) {
        boolean surroundedByDoubleQuotes = isQuoted(concatenatedValues);
        boolean surroundedBySingleQuotes = concatenatedValues.startsWith("'") && concatenatedValues.endsWith("'");

        // Remove surrounding quotes
        if (surroundedByDoubleQuotes || surroundedBySingleQuotes) {
            concatenatedValues = concatenatedValues.substring(1, concatenatedValues.length() - 1);
        }

        // Filter out tokens containing '$' and rejoin
        concatenatedValues = Arrays.stream(concatenatedValues.split(" "))
                .filter(token -> !token.contains("$"))
                .collect(Collectors.joining(" "))
                .trim();

        // Re-add quotes if they were originally present
        if (surroundedByDoubleQuotes) {
            concatenatedValues = quote(concatenatedValues);
        } else if (surroundedBySingleQuotes) {
            concatenatedValues = "'" + concatenatedValues + "'";
        }

        return concatenatedValues;
    }

    private List<String> parseCommaSeparatedValues(String value) {
        String[] values = value.split(",");
        List<String> list = new ArrayList<>();
        for (String v : values) {
            list.add(v.trim());
        }
        return list;
    }

    private List<String> parseCommaSeparatedValues(String[] values) {
        List<String> list = new ArrayList<>();
        for (String value : values) {
            list.addAll(parseCommaSeparatedValues(value));
        }
        return list;
    }

    private List<String> parseKeyValuePairs(String[] values) {
        List<String> list = new ArrayList<>();
        for (String value : values) {
            list.add(value.trim());
        }
        return list;
    }

}
