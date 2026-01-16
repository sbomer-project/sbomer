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
package org.jboss.sbomer.service.feature;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.sbomer.core.features.sbom.enums.GenerationRequestType;
import org.jboss.sbomer.core.features.sbom.utils.ObjectMapperProvider;

import com.fasterxml.jackson.core.JsonProcessingException;

import io.getunleash.FeatureToggle;
import io.getunleash.Unleash;
import io.getunleash.event.UnleashSubscriber;
import io.getunleash.repository.FeatureToggleResponse;
import io.quarkus.arc.Unremovable;
import io.vertx.mutiny.core.eventbus.EventBus;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;

/**
 * An entrypoint for all feature flags supported in SBOMer.
 */
@ApplicationScoped
@Unremovable
@Slf4j
public class FeatureFlags implements UnleashSubscriber {
    public static final String EVENT_NAME = "feature-flag-state-change";
    public static final String TOGGLE_DRY_RUN = "dry-run";
    public static final String TOGGLE_S3_STORAGE = "s3-storage";

    // UMB notifications
    public static final String TOGGLE_NOTIFY_CONTAINERIMAGE = "notify-containerimage";
    public static final String TOGGLE_NOTIFY_BUILD = "notify-build";
    public static final String TOGGLE_NOTIFY_OPERATION = "notify-operation";
    public static final String TOGGLE_NOTIFY_ANALYSIS = "notify-analysis";

    // Atlas
    public static final String TOGGLE_ATLAS_RELEASE_PUBLISH = "atlas-release-publish";
    public static final String TOGGLE_ATLAS_BUILD_PUBLISH = "atlas-build-publish";

    // Errata
    public static final String TOGGLE_ERRATA_INTEGRATION = "errata-integration";
    public static final String TOGGLE_STANDARD_ERRATA_RPM_MANIFEST_GENERATION = "errata-standard-rpm-manifest-generation";
    public static final String TOGGLE_STANDARD_ERRATA_IMAGE_MANIFEST_GENERATION = "errata-standard-image-manifest-generation";
    public static final String TOGGLE_TEXTONLY_ERRATA_MANIFEST_GENERATION = "errata-textonly-manifest-generation";
    public static final String TOGGLE_ERRATA_COMMENTS_GENERATION = "errata-comment-generation";
    // Release manifest configuration
    public static final String TOGGLE_STANDARD_ERRATA_RPM_RELEASE_MANIFEST_GENERATION = "errata-standard-rpm-release-manifest-generation";
    public static final String TOGGLE_STANDARD_ERRATA_IMAGE_RELEASE_MANIFEST_GENERATION = "errata-standard-image-release-manifest-generation";
    public static final String TOGGLE_TEXTONLY_ERRATA_RELEASE_MANIFEST_GENERATION = "errata-textonly-release-manifest-generation";

    // Syft
    public static final String TOGGLE_SYFT_MANIFEST_OPT = "syft-manifest-opt";

    /**
     * A map holding all toggle values we are interested in. This is used for logging purposes. We are retrieving the
     * state of the toggle via {@link Unleash} object instead.
     */
    private final Map<String, Boolean> toggleValues = new HashMap<>();

    @Inject
    Unleash unleash;

    @Inject
    EventBus bus;

    @ConfigProperty(name = "SBOMER_FEATURE_S3_STORAGE_ENABLED", defaultValue = "false")
    boolean s3StorageEnabled;

    @ConfigProperty(name = "SBOMER_FEATURE_NOTIFY_CONTAINERIMAGE_ENABLED", defaultValue = "false")
    boolean notifyContainerImage;

    @ConfigProperty(name = "SBOMER_FEATURE_ATLAS_PUBLISH_BUILD_ENABLED", defaultValue = "false")
    boolean publishToAtlasBuild;

    @ConfigProperty(name = "SBOMER_FEATURE_ATLAS_PUBLISH_RELEASE_ENABLED", defaultValue = "false")
    boolean publishToAtlasRelease;

    @ConfigProperty(name = "SBOMER_FEATURE_ERRATA_INTEGRATION_ENABLED", defaultValue = "false")
    boolean errataIntegration;

    @ConfigProperty(name = "SBOMER_FEATURE_STANDARD_ERRATA_RPM_MANIFEST_ENABLED", defaultValue = "false")
    boolean standardErrataRPMManifestGeneration;

    @ConfigProperty(name = "SBOMER_FEATURE_STANDARD_ERRATA_CONTAINERIMAGE_MANIFEST_ENABLED", defaultValue = "false")
    boolean standardErrataImageManifestGeneration;

    @ConfigProperty(name = "SBOMER_FEATURE_TEXTONLY_ERRATA_MANIFEST_ENABLED", defaultValue = "false")
    boolean textonlyErrataGeneration;

    @ConfigProperty(name = "SBOMER_FEATURE_ERRATA_COMMENTS_GENERATION_ENABLED", defaultValue = "false")
    boolean errataCommentsGeneration;

    @ConfigProperty(name = "SBOMER_FEATURE_STANDARD_ERRATA_RPM_RELEASE_MANIFEST_ENABLED", defaultValue = "false")
    boolean standardErrataRPMReleaseManifestGeneration;

    @ConfigProperty(
            name = "SBOMER_FEATURE_STANDARD_ERRATA_CONTAINERIMAGE_RELEASE_MANIFEST_ENABLED",
            defaultValue = "false")
    boolean standardErrataImageReleaseManifestGeneration;

    @ConfigProperty(name = "SBOMER_FEATURE_TEXTONLY_ERRATA_RELEASE_MANIFEST_ENABLED", defaultValue = "false")
    boolean textonlyErrataReleaseGeneration;

    @ConfigProperty(name = "SBOMER_FEATURE_SYFT_MANIFEST_OPT_ENABLED", defaultValue = "false")
    boolean syftManifestOpt;

    /**
     * Returns {@code true} in case the dry-run mode is enabled.
     *
     * @return {@code true} if dry-run is enabled, {@code false} otherwise
     */
    public boolean isDryRun() {
        return unleash.isEnabled(TOGGLE_DRY_RUN, false);
    }

    /**
     * Returns {@code true} if storing logs in S3 bucket is enabled.
     *
     * @return {@code true} if s3 support for logs is enabled, {@code false} otherwise
     */
    public boolean s3Storage() {
        return unleash.isEnabled(TOGGLE_S3_STORAGE, s3StorageEnabled);
    }

    /**
     * Returns {@code true} if uploading manifest to Atlas Release instance is enabled.
     *
     * @return {@code true} if uploading to atlas release is enabled, {@code false} otherwise
     */
    public boolean atlasReleasePublish() {
        return unleash.isEnabled(TOGGLE_ATLAS_RELEASE_PUBLISH, publishToAtlasRelease);
    }

    /**
     * Returns {@code true} if uploading manifest to Atlas Build instance is enabled.
     *
     * @return {@code true} if uploading to atlas build is enabled, {@code false} otherwise
     */
    public boolean atlasBuildPublish() {
        return unleash.isEnabled(TOGGLE_ATLAS_BUILD_PUBLISH, publishToAtlasBuild);
    }

    /**
     * Returns {@code true} if reading from Errata API is enabled.
     *
     * @return {@code true} if the integration with Errata API is enabled, {@code false} otherwise
     */
    public boolean errataIntegrationEnabled() {
        return unleash.isEnabled(TOGGLE_ERRATA_INTEGRATION, errataIntegration);
    }

    /**
     * Returns {@code true} if the manifest generation of standard Errata RPM builds is enabled.
     *
     * @return {@code true} if the manifest generation of standard Errata RPM builds is enabled, {@code false} otherwise
     */
    public boolean standardErrataRPMManifestGenerationEnabled() {
        return unleash.isEnabled(TOGGLE_STANDARD_ERRATA_RPM_MANIFEST_GENERATION, standardErrataRPMManifestGeneration);
    }

    /**
     * Returns {@code true} if the manifest generation of standard Errata container images builds is enabled.
     *
     * @return {@code true} if the manifest generation of standard Errata container images builds is enabled,
     *         {@code false} otherwise
     */
    public boolean standardErrataImageManifestGenerationEnabled() {
        return unleash
                .isEnabled(TOGGLE_STANDARD_ERRATA_IMAGE_MANIFEST_GENERATION, standardErrataImageManifestGeneration);
    }

    /**
     * Returns {@code true} if the manifest generation of text-only Errata is enabled.
     *
     * @return {@code true} if the manifest generation of text-only Errata is enabled, {@code false} otherwise
     */
    public boolean textOnlyErrataManifestGenerationEnabled() {
        return unleash.isEnabled(TOGGLE_TEXTONLY_ERRATA_MANIFEST_GENERATION, textonlyErrataGeneration);
    }

    /**
     * Returns {@code true} if the manifest generation should be reflected in Errata comments.
     *
     * @return {@code true} if the manifest generation should be reflected in Errata comments, {@code false} otherwise
     */
    public boolean errataCommentsGenerationsEnabled() {
        return unleash.isEnabled(TOGGLE_ERRATA_COMMENTS_GENERATION, errataCommentsGeneration);
    }

    /**
     * Returns {@code true} if the release manifest generation of standard Errata RPM builds is enabled.
     *
     * @return {@code true} if the release manifest generation of standard Errata RPM builds is enabled, {@code false}
     *         otherwise
     */
    public boolean standardErrataRPMReleaseManifestGenerationEnabled() {
        return unleash.isEnabled(
                TOGGLE_STANDARD_ERRATA_RPM_RELEASE_MANIFEST_GENERATION,
                standardErrataRPMReleaseManifestGeneration);
    }

    /**
     * Returns {@code true} if the release manifest generation of standard Errata container images builds is enabled.
     *
     * @return {@code true} if the release manifest generation of standard Errata container images builds is enabled,
     *         {@code false} otherwise
     */
    public boolean standardErrataImageReleaseManifestGenerationEnabled() {
        return unleash.isEnabled(
                TOGGLE_STANDARD_ERRATA_IMAGE_RELEASE_MANIFEST_GENERATION,
                standardErrataImageReleaseManifestGeneration);
    }

    /**
     * Returns {@code true} if the release manifest generation of text-only Errata is enabled.
     *
     * @return {@code true} if the release manifest generation of text-only Errata is enabled, {@code false} otherwise
     */
    public boolean textOnlyErrataReleaseManifestGenerationEnabled() {
        return unleash.isEnabled(TOGGLE_TEXTONLY_ERRATA_RELEASE_MANIFEST_GENERATION, textonlyErrataReleaseGeneration);
    }

    /**
     * Returns {@code true} if the Syft manifest optimization is enabled. When enabled, the paths argument will be set
     * to ["/opt"] for Syft image generation.
     *
     * @return {@code true} if Syft manifest optimization is enabled, {@code false} otherwise
     */
    public boolean syftManifestOptEnabled() {
        return unleash.isEnabled(TOGGLE_SYFT_MANIFEST_OPT, syftManifestOpt);
    }

    /**
     * Returns {@code true} if we should send a UMB message for a successfully generated manifest where the generation
     * request source is of a given type.
     *
     * @return {@code true} if the message should be sent, {@code false} otherwise
     */
    public boolean shouldNotify(GenerationRequestType type) {
        return switch (type) {
            case BUILD -> unleash.isEnabled(TOGGLE_NOTIFY_BUILD, false);
            case CONTAINERIMAGE -> unleash.isEnabled(TOGGLE_NOTIFY_CONTAINERIMAGE, notifyContainerImage);
            case OPERATION -> unleash.isEnabled(TOGGLE_NOTIFY_OPERATION, false);
            case ANALYSIS -> unleash.isEnabled(TOGGLE_NOTIFY_ANALYSIS, false);
            default -> false;
        };

    }

    private void updateToggles(final FeatureToggleResponse toggleResponse) {
        for (String toggleName : Set.of(
                TOGGLE_DRY_RUN,
                TOGGLE_S3_STORAGE,
                TOGGLE_NOTIFY_CONTAINERIMAGE,
                TOGGLE_NOTIFY_BUILD,
                TOGGLE_NOTIFY_OPERATION,
                TOGGLE_NOTIFY_ANALYSIS,
                TOGGLE_ATLAS_BUILD_PUBLISH,
                TOGGLE_ATLAS_RELEASE_PUBLISH,
                TOGGLE_ERRATA_INTEGRATION,
                TOGGLE_STANDARD_ERRATA_RPM_MANIFEST_GENERATION,
                TOGGLE_STANDARD_ERRATA_IMAGE_MANIFEST_GENERATION,
                TOGGLE_TEXTONLY_ERRATA_MANIFEST_GENERATION,
                TOGGLE_ERRATA_COMMENTS_GENERATION,
                TOGGLE_STANDARD_ERRATA_RPM_RELEASE_MANIFEST_GENERATION,
                TOGGLE_STANDARD_ERRATA_IMAGE_RELEASE_MANIFEST_GENERATION,
                TOGGLE_TEXTONLY_ERRATA_RELEASE_MANIFEST_GENERATION,
                TOGGLE_SYFT_MANIFEST_OPT)) {
            FeatureToggle toggle = toggleResponse.getToggleCollection().getToggle(toggleName);
            Boolean previousValue = toggleValues.put(toggleName, toggle.isEnabled());

            if (previousValue == null || previousValue != toggle.isEnabled()) {
                log.info("Feature toggle {} was just {}", toggleName, toggle.isEnabled() ? "enabled" : "disabled");
                bus.publish(EVENT_NAME, Map.of(toggleName, toggle.isEnabled()));
            }
        }

        try {
            log.debug("Current feature toggles: {}", ObjectMapperProvider.json().writeValueAsString(toggleValues));
        } catch (JsonProcessingException e) {
            // Ignored
        }
    }

    /**
     * A callback which will be called when feature flags are retrieved.
     */
    @Override
    public void togglesFetched(FeatureToggleResponse toggleResponse) {
        switch (toggleResponse.getStatus()) {
            case CHANGED -> {
                log.debug("Feature flags change detected, processing...");
                updateToggles(toggleResponse);
            }
            case NOT_CHANGED -> log.trace("No changes detected to feature flags");
            default -> log.warn("Unknown status: {}", toggleResponse.getStatus());
        }
    }
}
