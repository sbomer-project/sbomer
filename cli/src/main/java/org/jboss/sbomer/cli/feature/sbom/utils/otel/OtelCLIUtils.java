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
package org.jboss.sbomer.cli.feature.sbom.utils.otel;

import java.util.Map;

import org.jboss.pnc.common.otel.OtelUtils;
import org.jboss.sbomer.core.features.sbom.utils.MDCUtils;
import org.jboss.sbomer.core.features.sbom.utils.OtelHelper;

import io.opentelemetry.api.trace.Span;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class OtelCLIUtils {

    public static final String OTEL_TRACE_ID_ENV_VARIABLE = "TRACE_ID";
    public static final String OTEL_SPAN_ID_ENV_VARIABLE = "SPAN_ID";
    public static final String OTEL_TRACEPARENT_ENV_VARIABLE = "TRACEPARENT";
    public static final String OTEL_EXPORTER_OTLP_ENDPOINT_ENV_VARIABLE = "OTEL_EXPORTER_OTLP_ENDPOINT";
    public static final String SBOMER_SERVICE_NAME = "sbomer";
    public static final String SBOMER_CLI_NAME = "sbomer-cli";

    public static Map<String, String> getOtelContextFromEnvVariables() {
        String traceId = System.getenv(OTEL_TRACE_ID_ENV_VARIABLE);
        String spanId = System.getenv(OTEL_SPAN_ID_ENV_VARIABLE);
        String traceParent = System.getenv(OTEL_TRACEPARENT_ENV_VARIABLE);

        if (traceId == null) {
            traceId = Span.getInvalid().getSpanContext().getTraceId();
        }
        if (spanId == null) {
            spanId = Span.getInvalid().getSpanContext().getSpanId();
        }
        if (traceParent == null) {
            traceParent = OtelUtils
                    .createTraceParent(traceId, spanId, Span.getInvalid().getSpanContext().getTraceFlags().asHex());
        }

        return Map.of(
                MDCUtils.MDC_TRACE_ID_KEY,
                traceId,
                MDCUtils.MDC_SPAN_ID_KEY,
                spanId,
                MDCUtils.MDC_TRACEPARENT_KEY,
                traceParent);
    }

    /**
     * Start Otel exporters. The {@link OtelHelper} class will be used for this purpose.
     */
    public static void startOtel(String serviceName, String commandName, Map<String, String> attributes) {
        String endpoint = System.getenv(OTEL_EXPORTER_OTLP_ENDPOINT_ENV_VARIABLE);

        if (endpoint != null) {
            log.info("Enabling OpenTelemetry collection on {} with service name {}", endpoint, SBOMER_SERVICE_NAME);
            try {
                OtelHelper.startOTel(
                        serviceName,
                        commandName,
                        OtelHelper.defaultSpanProcessor(OtelHelper.defaultSpanExporter(endpoint)),
                        attributes);
            } catch (IllegalStateException exc) {
                log.trace("GlobalOpenTelemetry.set has already been called, safely silencing the exception here");
            } catch (Exception exc) {
                log.error("Error encountered when starting OTEL", exc);
            }
        }
    }

    /**
     * Stop Otel exporters. The {@link OtelHelper} class will be used for this purpose.
     */
    public static void stopOTel() {
        OtelHelper.stopOTel();
    }

}
