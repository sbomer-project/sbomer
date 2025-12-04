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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.eclipse.jgit.transport.URIish;

import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;

/**
 * A Version Control System (VCS) URL that allows conversion to a {@link PackageURL.StandardTypes#GENERIC generic}
 * {@link PackageURL} with the
 * <a href="https://github.com/package-url/purl-spec/blob/main/docs/known-qualifiers.md">known qualifier</a>
 * {@code vcs_url} set or to a {@link URI}.
 *
 * <p>
 * Supported URLs:
 * </p>
 * <ul>
 * <li><b>SPDX VCS</b> of the form
 * {@code <vcs_tool>+<transport>://<host_name>[/<path_to_repository>][@<revision_tag_or_branch>][#<sub_path>]}. See:
 * <a href="https://spdx.github.io/spdx-spec/v2.3/package-information/#771-description">SPDX v2.3 &sect;7.7.1 Package
 * download location field description</a></li>
 * <li><b>Git</b>, including SCP-like SSH syntax, of the form {@code user@host:org/repo.git}. See:
 * <a href="https://git-scm.com/docs/git-clone#_git_urls">Git Clone &sect; Git URLs</a></li>
 * <li><b>NPM Git</b>, such as: {@code git+ssh://git@github.com/user/repo.git#ref}, where {@code #ref} specifies a Git
 * tag, branch, or other Git ref. See: <a href="https://docs.npmjs.com/cli/v11/using-npm/package-spec#git-urls">NPM
 * Package name specifier &sect; Git URLs</a></li>
 * </ul>
 *
 * @author David Walluck
 */
public record VcsUrl(String tool, String transport, String host, String path, String revision, String subpath) {

    private static final char TOOL_DELIM = '+';

    private static final char SUBPATH_DELIM = '#';

    private static final char REVISION_DELIM = '@';

    /**
     * The default VCS tool (git).
     */
    public static final String DEFAULT_TOOL = "git";

    /**
     * The default VCS scheme if none is present (ssh).
     */
    public static final String DEFAULT_SCHEME = "ssh";

    /**
     * Creates a VcsUrl from a URL string.
     *
     * @param str the URL
     * @return a new VCS URL
     * @throws IllegalArgumentException if the URL is invalid
     */
    public static VcsUrl create(final String str) {
        Objects.requireNonNull(str, "str");

        try {
            URIish uriish = new URIish(str);
            String host = uriish.getHost();

            if (StringUtils.isEmpty(host)) {
                throw new IllegalArgumentException("host is empty");
            }

            boolean vcsUrl = false;
            String scheme = uriish.getScheme();
            String vcsTool;
            String transport;

            if (scheme != null) {
                int toolIdx = scheme.indexOf(TOOL_DELIM);

                if (toolIdx != -1) {
                    vcsTool = scheme.substring(0, toolIdx);

                    if (vcsTool.isEmpty()) {
                        throw new IllegalArgumentException("vcsTool is empty");
                    }

                    transport = scheme.substring(toolIdx + 1);

                    if (transport.isEmpty()) {
                        throw new IllegalArgumentException("transport is empty");
                    }

                    vcsUrl = true;
                } else {
                    vcsTool = DEFAULT_TOOL;
                    transport = scheme;
                }
            } else {
                vcsTool = DEFAULT_TOOL;
                transport = DEFAULT_SCHEME;
            }

            String path = uriish.getPath();
            String revision = null;
            String subpath = null;

            if (path != null) {
                path = StringUtils.removeStart(FilenameUtils.normalizeNoEndSeparator(path, true), '/');
                int subpathIdx = path.indexOf(SUBPATH_DELIM);
                String fragment = null;

                if (subpathIdx != -1) {
                    fragment = path.substring(subpathIdx + 1);
                    path = path.substring(0, subpathIdx);
                }

                int revisionIdx = path.indexOf(REVISION_DELIM);

                if (revisionIdx != -1) {
                    revision = path.substring(revisionIdx + 1);

                    if (revision.isEmpty()) {
                        throw new IllegalArgumentException("revision is empty");
                    }

                    path = path.substring(0, revisionIdx);
                }

                if (vcsUrl || revisionIdx != -1) {
                    subpath = fragment;
                } else {
                    revision = fragment;
                }
            }

            return new VcsUrl(vcsTool, transport, host, path, revision, subpath);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid VCS URL: " + str, e);
        }
    }

    /**
     * Converts this CVS URL to a {@link URI}.
     *
     * @return the new URI
     */
    public URI toURI() {
        try {
            return new URI(
                    transport,
                    host,
                    Strings.CI.prependIfMissing(path, "/"),
                    null,
                    subpath != null ? subpath : revision);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Converts this VcsUrl into a generic PackageURL and the SPDX vcs_url qualifier.
     *
     * @param revision revision override (e.g., the commit hash if another ref is used)
     * @return the constructed PackageURL
     */
    public PackageURL toPackageURL(String revision) {
        try {
            int slashIdx = StringUtils.lastIndexOf(path, '/');
            String name;
            String namespace;

            if (slashIdx == -1) {
                name = path;
                namespace = host;
            } else {
                name = path.substring(slashIdx + 1);
                String subpath = path.substring(0, slashIdx);
                namespace = subpath.isEmpty() ? host
                        : FilenameUtils.normalize(FilenameUtils.concat(host, subpath), true);
            }

            name = Strings.CS.removeEnd(name, ".git");
            return PackageURLBuilder.aPackageURL()
                    .withType(PackageURL.StandardTypes.GENERIC)
                    .withNamespace(namespace)
                    .withName(name)
                    .withVersion(revision)
                    .withQualifier("vcs_url", this.toString())
                    .withSubpath(subpath)
                    .build();
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to build PackageURL from VcsUrl", e);
        }
    }

    /**
     * Converts this VcsUrl into a generic PackageURL and the SPDX vcs_url qualifier.
     *
     * @return the constructed PackageURL
     */
    public PackageURL toPackageURL() {
        return toPackageURL(revision);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(tool).append(TOOL_DELIM).append(transport).append("://").append(host);

        if (path != null) {
            sb.append('/').append(path);
        }

        if (revision != null) {
            sb.append(REVISION_DELIM).append(revision);
        }

        if (subpath != null) {
            sb.append(SUBPATH_DELIM).append(subpath);
        }

        return sb.toString();
    }
}
