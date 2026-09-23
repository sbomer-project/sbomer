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
package org.jboss.sbomer.service.scheduler;

import java.time.Duration;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import jakarta.enterprise.context.ApplicationScoped;

/**
 * Configuration for the {@link GenerationRequestReaper}, which fails generations that have been stuck in a non-terminal
 * status for longer than {@link #timeout()}.
 */
@ApplicationScoped
@ConfigMapping(prefix = "sbomer.service.generation-reaper")
public interface GenerationReaperConfig {

    /**
     * Whether the reaper is enabled. When disabled, stuck generations will only ever be failed by the (much longer)
     * Tekton TaskRun timeout, and only if the operator observes the TaskRun transition.
     */
    @WithDefault("true")
    boolean enabled();

    /**
     * The interval on which the reaper will run.
     */
    @WithDefault("10m")
    String interval();

    /**
     * The maximum total duration a generation is allowed to spend in a non-terminal status (measured from its creation
     * time). Any generation older than this that has not reached FINISHED/FAILED is failed by the reaper.
     */
    @WithDefault("24h")
    Duration timeout();
}
