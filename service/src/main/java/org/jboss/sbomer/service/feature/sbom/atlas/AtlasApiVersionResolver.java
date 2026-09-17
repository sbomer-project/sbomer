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

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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
 * {@code /.well-known/trustify} endpoint and cached per instance.
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

    /** The API version in {@code /api/v3/} landed with Trustify 0.5.0. */
    static final int V3_MIN_MAJOR = 0;
    static final int V3_MIN_MINOR = 5;

    /** How long a resolved version is trusted before the server is probed again. */
    static final Duration CACHE_TTL = Duration.ofHours(1);

    @Inject
    @RestClient
    AtlasBuildInfoClient atlasBuildInfoClient;

    @Inject
    @RestClient
    AtlasReleaseInfoClient atlasReleaseInfoClient;

    @Inject
    FeatureFlags featureFlags;

    private record CachedVersion(String apiVersion, Instant resolvedAt) {
        boolean isExpired() {
            return Instant.now().isAfter(resolvedAt.plus(CACHE_TTL));
        }
    }

    private final Map<Boolean, CachedVersion> cache = new ConcurrentHashMap<>();

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

        CachedVersion cached = cache.get(isRelease);
        if (cached != null && !cached.isExpired()) {
            return cached.apiVersion();
        }

        String apiVersion = detect(isRelease);
        cache.put(isRelease, new CachedVersion(apiVersion, Instant.now()));
        return apiVersion;
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
     * Returns {@code true} if the provided server version string is {@code >= 0.5.0}, i.e. exposes the {@code /api/v3/}
     * API. Unparseable or blank versions are treated as below the threshold ({@code v2}).
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

            return major > V3_MIN_MAJOR || (major == V3_MIN_MAJOR && minor >= V3_MIN_MINOR);
        } catch (NumberFormatException e) {
            log.warn("Unable to parse Atlas server version '{}', assuming API version '{}'", version, V2);
            return false;
        }
    }
}
