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

import java.util.regex.Pattern;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

public class OpenJdkGenericPurlWrapperUtil extends GenericPurlWrapperUtil {

    private static final Pattern[] OPENJDK_VERSION_REGEX_STRATEGIES = {
            Pattern.compile("(?<version>\\d+\\.\\d+\\.\\d+\\.\\d+\\.b\\d+-\\d+)"),
            Pattern.compile("(?<version>\\d+\\.\\d+\\.\\d+)(?<qualsep>[.-](?<qualifier>Final|[A-Z]+\\d*))?"),
            Pattern.compile("(?<version>\\d+\\.\\d+)(?<qualsep>[.-](?<qualifier>[A-Z]+\\d*))?"),
            Pattern.compile("(?<version>\\d+_\\d+)(?<qualsep>[.-](?<qualifier>[A-Z]+\\d*))?") };

    private static final Pattern OPENJDK_NAME_PATTERN = Pattern.compile("java-.*-openjdk|java-openjdk");

    public OpenJdkGenericPurlWrapperUtil(String purl) throws MalformedPackageURLException {
        super(purl);
    }

    public OpenJdkGenericPurlWrapperUtil(PackageURL purl) throws MalformedPackageURLException {
        super(purl);
    }

    @Override
    protected Pattern[] getVersionRegexStrategies() {
        return OPENJDK_VERSION_REGEX_STRATEGIES;
    }

    public static boolean isOpenJdkPurl(PackageURL purl) {
        return purl != null && "generic".equals(purl.getType()) && OPENJDK_NAME_PATTERN.matcher(purl.getName()).find();
    }

    public static boolean isOpenJdkPurl(String purlName) {
        return purlName != null && OPENJDK_NAME_PATTERN.matcher(purlName).find();
    }
}
