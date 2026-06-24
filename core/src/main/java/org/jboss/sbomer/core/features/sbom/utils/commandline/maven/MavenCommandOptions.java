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

import java.util.List;

import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

public class MavenCommandOptions {

    private static final String COMPATIBILITY_DESC = "Ineffective, only kept for backward compatibility";

    private static final String ALSO_MAKE_OPTION = "am";
    private static final String ALSO_MAKE_DEPENDENTS_OPTION = "amd";
    private static final String STRICT_CHECKSUM_OPTION = "C";
    private static final String LAX_CHECKSUM_OPTION = "c";
    private static final String NON_RECURSIVE_OPTION = "N";

    public static final String PROFILES_OPTION = "P";
    public static final String SYSTEM_PROPERTIES_OPTION = "D";
    public static final String PROJECTS_OPTION = "pl";
    public static final String ALTERNATE_POM = "f";

    public static final List<String> NO_ARGS_OPTIONS = List.of(
            ALSO_MAKE_OPTION,
            ALSO_MAKE_DEPENDENTS_OPTION,
            STRICT_CHECKSUM_OPTION,
            LAX_CHECKSUM_OPTION,
            NON_RECURSIVE_OPTION);

    private MavenCommandOptions() {
        // This is a utility class
    }

    /**
     * Add ineffective maven command options kept for backward compatibility
     *
     * @param options the options to add the ineffective options to
     * @return the options with the ineffective options added
     */
    public static Options addIneffectiveOptions(Options options) {
        options.addOption(
                Option.builder("cpu").longOpt("check-plugin-updates").hasArg(false).desc(COMPATIBILITY_DESC).build());
        options.addOption(
                Option.builder("npr").longOpt("no-plugin-registry").hasArg(false).desc(COMPATIBILITY_DESC).build());
        options.addOption(
                Option.builder("npu").longOpt("no-plugin-updates").hasArg(false).desc(COMPATIBILITY_DESC).build());
        options.addOption(
                Option.builder("up").longOpt("update-plugins").hasArg(false).desc(COMPATIBILITY_DESC).build());

        return options;
    }

    /**
     * Add maven command options which should be ignored but should be parsed
     *
     * @param options the options to add the ignorable options to
     * @return the options with the ignorable options added
     */
    public static Options addIgnorableOptions(Options options) {
        options.addOption(
                Option.builder("b")
                        .longOpt("builder")
                        .hasArg(true)
                        .desc("The id of the build strategy to use")
                        .build());
        options.addOption(
                Option.builder("B")
                        .longOpt("batch-mode")
                        .hasArg(false)
                        .desc("Run in non-interactive (batch) mode (disables output color)")
                        .build());
        options.addOption(
                Option.builder("e").longOpt("errors").hasArg(false).desc("Produce execution error messages").build());
        options.addOption(
                Option.builder("fae")
                        .longOpt("fail-at-end")
                        .hasArg(false)
                        .desc("Only fail the build afterwards; allow all non-impacted builds to continue")
                        .build());
        options.addOption(
                Option.builder("ff")
                        .longOpt("fail-fast")
                        .hasArg(false)
                        .desc("Stop at first failure in reactorized builds")
                        .build());
        options.addOption(
                Option.builder("fn")
                        .longOpt("fail-never")
                        .hasArg(false)
                        .desc("NEVER fail the build, regardless of project result")
                        .build());
        options.addOption(Option.builder("h").longOpt("help").hasArg(false).desc("Display help information").build());
        options.addOption(
                Option.builder("l")
                        .longOpt("log-file")
                        .hasArg(true)
                        .desc("Log file where all build output will go (disables output color)")
                        .build());
        options.addOption(
                Option.builder("llr")
                        .longOpt("legacy-local-repository")
                        .hasArg(false)
                        .desc(
                                "Use Maven 2 Legacy Local Repository behaviour, ie no use of _remote.repositories. Can also be activated by using -Dmaven.legacyLocalRepo=true")
                        .build());
        options.addOption(
                Option.builder("nsu")
                        .longOpt("no-snapshot-updates")
                        .hasArg(false)
                        .desc("Suppress SNAPSHOT updates")
                        .build());
        options.addOption(
                Option.builder("ntp")
                        .longOpt("no-transfer-progress")
                        .hasArg(false)
                        .desc("Do not display transfer progress when downloading or uploading")
                        .build());
        options.addOption(Option.builder("o").longOpt("offline").hasArg(false).desc("Work offline").build());
        options.addOption(
                Option.builder("q").longOpt("quiet").hasArg(false).desc("Quiet output - only show errors").build());
        options.addOption(
                Option.builder("U")
                        .longOpt("update-snapshots")
                        .hasArg(false)
                        .desc("Forces a check for missing releases and updated snapshots on remote repositories")
                        .build());
        options.addOption(
                Option.builder("v").longOpt("version").hasArg(false).desc("Display version information").build());
        options.addOption(
                Option.builder("V")
                        .longOpt("show-version")
                        .hasArg(false)
                        .desc("Display version information WITHOUT stopping build")
                        .build());
        options.addOption(
                Option.builder("X").longOpt("debug").hasArg(false).desc("Produce execution debug output").build());
        options.addOption(
                Option.builder("color")
                        .longOpt("color")
                        .hasArg()
                        .desc("Defines the color mode of the output. Supported are 'auto', 'always', 'never'.")
                        .build());
        options.addOption(
                Option.builder("emp")
                        .longOpt("encrypt-master-password")
                        .hasArg()
                        .desc("Encrypt master security password")
                        .build());
        options.addOption(
                Option.builder("ep").longOpt("encrypt-password").hasArg().desc("Encrypt server password").build());
        options.addOption(
                Option.builder("rf")
                        .longOpt("resume-from")
                        .hasArg()
                        .desc("Resume reactor from specified project")
                        .build());
        options.addOption(
                Option.builder("s")
                        .longOpt("settings")
                        .hasArg()
                        .desc("Alternate path for the user settings file")
                        .build());
        options.addOption(
                Option.builder("t")
                        .longOpt("toolchains")
                        .hasArg()
                        .desc("Alternate path for the user toolchains file")
                        .build());
        options.addOption(
                Option.builder("T")
                        .longOpt("threads")
                        .hasArg()
                        .desc("Thread count, for instance 2.0C where C is core multiplied")
                        .build());

        // I don't think PNC will handle these
        options.addOption(
                Option.builder("gs")
                        .longOpt("global-settings")
                        .hasArg(true)
                        .desc("Alternate path for the global settings file")
                        .build());
        options.addOption(
                Option.builder("gt")
                        .longOpt("global-toolchains")
                        .hasArg(true)
                        .desc("Alternate path for the global toolchains file")
                        .build());

        return options;
    }

    /**
     * Add maven command options which do not have any argument
     *
     * @param options the options to add the no-args options to
     * @return the options with the no-args options added
     */
    public static Options addNoArgsOptions(Options options) {
        options.addOption(
                Option.builder(ALSO_MAKE_OPTION)
                        .longOpt("also-make")
                        .hasArg(false)
                        .desc("If project list is specified, also build projects required by the list")
                        .build());
        options.addOption(
                Option.builder(ALSO_MAKE_DEPENDENTS_OPTION)
                        .longOpt("also-make-dependents")
                        .hasArg(false)
                        .desc("If project list is specified, also build projects that depend on projects on the list")
                        .build());
        options.addOption(
                Option.builder(STRICT_CHECKSUM_OPTION)
                        .longOpt("strict-checksums")
                        .hasArg(false)
                        .desc("Fail the build if checksums don't match")
                        .build());
        options.addOption(
                Option.builder(LAX_CHECKSUM_OPTION)
                        .longOpt("lax-checksums")
                        .hasArg(false)
                        .desc("Warn if checksums don't match")
                        .build());
        options.addOption(
                Option.builder(NON_RECURSIVE_OPTION)
                        .longOpt("non-recursive")
                        .hasArg(false)
                        .desc("Do not recurse into sub-projects")
                        .build());

        return options;
    }

    /**
     * Add command line provided system properties
     *
     * @param options the options to add the system property options to
     * @return the options with the system property options added
     */
    public static Options addSystemPropertyOptions(Options options) {
        options.addOption(
                Option.builder(SYSTEM_PROPERTIES_OPTION)
                        .longOpt("define")
                        .argName("property[=value]")
                        .hasArgs()
                        .valueSeparator()
                        .desc("Define system properties")
                        .build());

        return options;
    }

    /**
     * Add maven command options to parse profiles
     *
     * @param options the options to add the profiles options to
     * @return the options with the profiles options added
     */
    public static Options addProfilesOptions(Options options) {
        options.addOption(
                Option.builder(PROFILES_OPTION)
                        .longOpt("activate-profiles")
                        .valueSeparator(',')
                        .hasArg()
                        .desc("Specify profiles")
                        .build());

        return options;
    }

    /**
     * Add maven command options to parse projects
     *
     * @param options the options to add the projects options to
     * @return the options with the projects options added
     */
    public static Options addProjectsOptions(Options options) {
        options.addOption(
                Option.builder(PROJECTS_OPTION)
                        .longOpt("projects")
                        .valueSeparator(',')
                        .hasArg()
                        .desc(
                                "Comma-delimited list of specified reactor projects to build instead of all projects. A project can be specified by [groupId]:artifactId or by its relative path")
                        .build());

        return options;
    }

    /**
     * Add maven command options to parse pom alternate locations
     *
     * @param options the options to add the alternate pom options to
     * @return the options with the alternate pom options added
     */
    public static Options addAlternatePomOption(Options options) {
        options.addOption(
                Option.builder(ALTERNATE_POM)
                        .longOpt("file")
                        .hasArg()
                        .desc("Force the use of an alternate POM file (or directory with pom.xml)")
                        .build());

        return options;
    }

}
