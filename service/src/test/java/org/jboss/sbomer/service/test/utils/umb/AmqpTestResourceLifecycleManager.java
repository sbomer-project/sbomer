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
package org.jboss.sbomer.service.test.utils.umb;

import java.util.HashMap;
import java.util.Map;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import io.smallrye.reactive.messaging.memory.InMemoryConnector;

public class AmqpTestResourceLifecycleManager implements QuarkusTestResourceLifecycleManager {
    @Override
    public Map<String, String> start() {
        Map<String, String> env = new HashMap<>();
        // Switch all AMQP messaging channels to in-memory for tests
        Map<String, String> buildsProps = InMemoryConnector.switchIncomingChannelsToInMemory("builds");
        Map<String, String> errataProps = InMemoryConnector.switchIncomingChannelsToInMemory("errata");
        Map<String, String> finishedProps = InMemoryConnector.switchOutgoingChannelsToInMemory("finished");
        env.putAll(buildsProps);
        env.putAll(errataProps);
        env.putAll(finishedProps);
        env.putAll(
                Map.of(
                        "sbomer.features.umb.enabled",
                        "true",
                        "mp.messaging.outgoing.finished.address",
                        "topic://a-test-topic",
                        "sbomer.features.umb.producer.enabled",
                        "true"));
        return env;
    }

    @Override
    public void stop() {
        InMemoryConnector.clear();
    }
}
