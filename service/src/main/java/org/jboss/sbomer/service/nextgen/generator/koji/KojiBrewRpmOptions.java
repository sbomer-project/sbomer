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
package org.jboss.sbomer.service.nextgen.generator.koji;

import org.jboss.sbomer.service.nextgen.generator.GeneratorRetries;

/**
 * Representation of configuration options related to Koji generator. This is the representation of the {@code options}
 * field in {@link GeneratorConfig}.
 *
 * @see GeneratorConfig
 * @param timeout The timeout after which the generation should be terminated.
 * @param retries Generator retry configuration.
 * @param cbom Enable CBOM (Cryptographic Bill of Materials) generation. Default is false.
 * @param cbomTimeout Timeout for CBOM scan. Accepts Go duration syntax (e.g., "30m", "1h", "4h"). Default is "1h". Must
 *        be less than or equal to the Tekton TaskRun timeout (6h).
 */
public record KojiBrewRpmOptions(String timeout, GeneratorRetries retries, Boolean cbom, String cbomTimeout) {
}
