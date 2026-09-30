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
package org.jboss.sbomer.service.feature.sbom.atlas;

import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.sbomer.service.feature.FeatureFlags;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

/**
 * Resolves which Atlas (Trustify) API version to use for uploads.
 * <p>
 * Trustify moved its API from {@code /api/v2/} to {@code /api/v3/} in the 0.5.0 release. During the rollout SBOMer must
 * talk to whichever version a given Atlas instance runs, so the version is discovered at runtime via the
 * {@code /.well-known/trustify} endpoint. The probe is performed once per publish batch, against the same host the
 * manifests are uploaded to, so it is not cached.
 * <p>
 * The {@code atlas-force-v3} feature flag bypasses the network probe entirely and always selects {@code v3}; this lets
 * us drop the check once every Atlas instance has been upgraded.
 * <p>
 * If detection fails (server unreachable, no {@code /.well-known/trustify} endpoint on older servers, or an unparseable
 * version) the resolver falls back to {@code v2}, preserving the previous behaviour against not-yet-migrated servers.
 */
@Setter
@ApplicationScoped
@Slf4j
public class AtlasApiVersionResolver {

    public static final String V2 = "v2";
    public static final String V3 = "v3";

    /** Trustify uses a 0.x scheme; the {@code /api/v3/} API landed in Trustify 0.5.0. */
    static final int TRUSTIFY_MAJOR = 0;
    static final int TRUSTIFY_V3_MIN_MINOR = 5;

    /**
     * TPA (Trusted Profile Analyzer) uses its own scheme: the 2.x line still serves {@code /api/v2/}, while 3.x is
     * expected to serve {@code /api/v3/}.
     */
    static final int TPA_V3_MIN_MAJOR = 3;

    @Inject
    @RestClient
    AtlasBuildInfoClient atlasBuildInfoClient;

    @Inject
    @RestClient
    AtlasReleaseInfoClient atlasReleaseInfoClient;

    @Inject
    FeatureFlags featureFlags;

    /**
     * Returns the Atlas API version segment ({@value #V2} or {@value #V3}) to use for the given instance.
     *
     * @param isRelease {@code true} for the release Atlas instance, {@code false} for the build instance
     * @return the API version segment
     */
    public String resolve(boolean isRelease) {
        if (featureFlags.atlasForceV3()) {
            log.debug("Atlas 'atlas-force-v3' flag is enabled, using API version '{}' without probing the server", V3);
            return V3;
        }

        return detect(isRelease);
    }

    private String detect(boolean isRelease) {
        String instanceName = isRelease ? "release" : "build";
        AtlasInfoClient infoClient = isRelease ? atlasReleaseInfoClient : atlasBuildInfoClient;

        try {
            AtlasInfo info = infoClient.info();
            String version = info != null ? info.getVersion() : null;

            if (supportsV3(version)) {
                log.info("Atlas {} instance reports version '{}', using API version '{}'", instanceName, version, V3);
                return V3;
            }

            log.info("Atlas {} instance reports version '{}', using API version '{}'", instanceName, version, V2);
            return V2;
        } catch (Exception e) {
            log.warn(
                    "Unable to determine Atlas {} instance version, falling back to API version '{}': {}",
                    instanceName,
                    V2,
                    e.getMessage());
            return V2;
        }
    }

    /**
     * Returns {@code true} if the provided server version string exposes the {@code /api/v3/} API. Two version schemes
     * are recognised: Trustify's 0.x line (v3 from {@code 0.5.0}) and TPA's line (2.x stays on v2, 3.x and above move
     * to v3). Unparseable or blank versions, and versions below the relevant threshold, are treated as {@code v2}. This
     * is only a best guess; a wrong result is recovered from by the upload's 404 fallback (see
     * {@link #otherApiVersion}).
     */
    public static boolean supportsV3(String version) {
        if (version == null || version.isBlank()) {
            return false;
        }

        // Strip any pre-release ("-rc.1") or build ("+meta") suffix, e.g. "0.6.0-rc.1" -> "0.6.0".
        String core = version.trim().split("[-+]", 2)[0];
        String[] parts = core.split("\\.");

        try {
            int major = Integer.parseInt(parts[0]);
            int minor = parts.length > 1 ? Integer.parseInt(parts[1]) : 0;

            // Trustify 0.x: /api/v3/ landed in 0.5.0.
            if (major == TRUSTIFY_MAJOR) {
                return minor >= TRUSTIFY_V3_MIN_MINOR;
            }

            // TPA scheme: the 2.x line serves /api/v2/, 3.x and above serve /api/v3/.
            return major >= TPA_V3_MIN_MAJOR;
        } catch (NumberFormatException e) {
            log.warn("Unable to parse Atlas server version '{}', assuming API version '{}'", version, V2);
            return false;
        }
    }

    /**
     * Returns the API version segment to fall back to when a server rejects {@code apiVersion} with a 404, i.e. the
     * other of {@value #V2}/{@value #V3}.
     */
    public static String otherApiVersion(String apiVersion) {
        return V3.equals(apiVersion) ? V2 : V3;
    }
}
