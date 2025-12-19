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
package org.jboss.sbomer.core.rest.faulttolerance;

public class Constants {

    public static final int PNC_CLIENT_MAX_RETRIES = 10;
    public static final int ERRATA_CLIENT_MAX_RETRIES = 15;
    public static final int PYXIS_CLIENT_MAX_RETRIES = 15;
    public static final int ATLAS_CLIENT_MAX_RETRIES = 9;
    public static final int KOJI_DOWNLOAD_CLIENT_MAX_RETRIES = 15;
    public static final int SBOMER_CLIENT_MAX_RETRIES = 15;

    public static final long PNC_CLIENT_DELAY = 1;
    public static final long ERRATA_CLIENT_DELAY = 1;
    public static final long PYXIS_CLIENT_DELAY = 1;
    public static final long ATLAS_CLIENT_DELAY = 60;
    public static final long ATLAS_CLIENT_MAX_DURATION = 18000; // (in seconds) - 5hrs
    public static final long ATLAS_CLIENT_BACKOFF_MAX_DELAY = 3600; // (in seconds) - 1 hour
    public static final long KOJI_DOWNLOAD_CLIENT_DELAY = 1;
    public static final long SBOMER_CLIENT_DELAY = 1;

    /*
     * In some circumstances Pyxis returns a 200 code but an empty RepositoryDescription, this means it may not yet be
     * published, this can take a long time (hours and days). The below settings apply to this scenario, as we are using
     * the fibonaci backoff we can work out the backoff intervals from intial delay and max retries, initially we will
     * aim for 2 days (48hrs) max backoff.
     *
     * Intial Delay = 60 minutes Max retries = 18 (2584 minutes - 1 day 19hrs 4minutes)
     *
     * Setting the ChronoUnit via constants is a bit over involved so please also refer to the location of the
     * annotation service/src/main/java/org/jboss/sbomer/service/feature/sbom/pyxis/PyxisValidatingClient.java, the
     * default is millis which is reflected in the below calcs but its possible to use more appropriate sized durations
     * with ChronoUnit.MINUTES for delayUnits
     */

    public static final long PYXIS_UNPUBLISHED_INITIAL_DELAY = 60 * 60 * 1000;
    public static final int PYXIS_UNPUBLISHED_MAX_RETRIES = 18;
    public static final long PYXIS_UNPUBLISHED_MAX_DURATION = (PYXIS_UNPUBLISHED_INITIAL_DELAY
            * (PYXIS_UNPUBLISHED_MAX_RETRIES + 1));
    public static final long PYXIS_UNPUBLISHED_MAX_DELAY = (PYXIS_UNPUBLISHED_INITIAL_DELAY
            * PYXIS_UNPUBLISHED_MAX_RETRIES);

    /*
     * In some circumstances when starting the sbomer service and there are a number of sucessful taskruns ready for
     * manifests to be ingested, this causes the service to become overloaded and slow with this sudden influx of heavy
     * i/o
     *
     * These properties are applied to a `Bulkhead` (essentially a queue that limits the number of concurrent
     * executions), it can concurrently process two manifests at a time, more and a `BulkheadException` is thrown
     *
     * MAX_QUEUE is not used but overrides the default if it where to be called Asyncronosuly and will throw
     * `BulkheadException` We set it just so we remember it exists if we are to call it async
     *
     * When a `BulkheadException` is thrown the Retry logic will re-attempt with an incremental backoff each time this
     * means MAX_RETRIES * DELAY, currently 640 seconds, @Retry will stop catching the exception at this point and the
     * Generation marked as FAILED
     */
    public static final int SBOM_IO_MAX_RETRIES = 7;
    public static final int SBOM_IO_DELAY = 10;
    public static final int SBOM_IO_CONCURENCY = 2;
    public static final int SBOM_IO_MAX_QUEUE = 10; // 10 is the microprofile default
}
