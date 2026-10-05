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
package org.jboss.sbomer.service.feature.sbom.runtime;

import org.jboss.sbomer.core.features.sbom.validation.SbomerJsonParser;
import org.jboss.sbomer.service.feature.FeatureFlags;

import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;

/**
 * Observes application startup and shutdown events and logs them
 *
 * @author Andrea Vibelli
 */
@ApplicationScoped
@Slf4j
public class ApplicationLifecycle {

    @Inject
    FeatureFlags featureFlags;

    void onStart(@Observes StartupEvent event) {
        // we need to log startup and shutdown events
        log.info("Application has started");
        SbomerJsonParser.load();
    }

    void onStop(@Observes ShutdownEvent event) {
        // we need to log startup and shutdown events
        log.info("The application is stopping");
    }
}
