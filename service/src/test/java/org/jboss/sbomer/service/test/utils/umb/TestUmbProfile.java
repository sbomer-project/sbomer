package org.jboss.sbomer.service.test.utils.umb;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jboss.sbomer.service.test.utils.AlternativeGeneratorConfigProvider;
import org.jboss.sbomer.service.test.utils.AlternativeRequestEventRepository;

import io.quarkus.test.junit.QuarkusTestProfile;

public class TestUmbProfile implements QuarkusTestProfile {
    @Override
    public Set<Class<?>> getEnabledAlternatives() {
        return Set.of(
                TestAmqpUmbClientOptionProducer.class,
                AlternativeRequestEventRepository.class,
                AlternativeGeneratorConfigProvider.class);
    }

    @Override
    public List<TestResourceEntry> testResources() {
        return List.of(new TestResourceEntry(AmqpTestResourceLifecycleManager.class));
    }

    /**
     * Override fault tolerance settings to prevent thread pool exhaustion in tests.
     *
     * Production bulkhead settings (SBOM_IO_CONCURENCY=2) are too restrictive for parallel tests hitting WireMock.
     * These overrides increase concurrency from 2→10 and reduce retry attempts from 7→3 for faster test execution.
     */
    @Override
    public Map<String, String> getConfigOverrides() {
        String abstractController = "org.jboss.sbomer.service.feature.sbom.features.generator.AbstractController";
        String buildController = "org.jboss.sbomer.service.feature.sbom.k8s.reconciler.BuildController";

        Map<String, String> overrides = new HashMap<>();

        // AbstractController.storeBoms
        overrides.put(abstractController + "/storeBoms/Bulkhead/value", "10");
        overrides.put(abstractController + "/storeBoms/Bulkhead/waitingTaskQueue", "20");
        overrides.put(abstractController + "/storeBoms/Retry/maxRetries", "3");
        overrides.put(abstractController + "/storeBoms/Retry/delay", "1");

        // AbstractController.readManifests
        overrides.put(abstractController + "/readManifests/Bulkhead/value", "10");
        overrides.put(abstractController + "/readManifests/Bulkhead/waitingTaskQueue", "20");
        overrides.put(abstractController + "/readManifests/Retry/maxRetries", "3");
        overrides.put(abstractController + "/readManifests/Retry/delay", "1");

        // BuildController.storeSboms
        overrides.put(buildController + "/storeSboms/Bulkhead/value", "10");
        overrides.put(buildController + "/storeSboms/Bulkhead/waitingTaskQueue", "20");
        overrides.put(buildController + "/storeSboms/Retry/maxRetries", "3");
        overrides.put(buildController + "/storeSboms/Retry/delay", "1");

        return overrides;
    }
}