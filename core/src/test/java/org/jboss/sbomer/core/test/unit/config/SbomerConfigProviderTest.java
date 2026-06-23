package org.jboss.sbomer.core.test.unit.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.jboss.sbomer.core.config.DefaultGenerationConfig;
import org.jboss.sbomer.core.config.SbomerConfigProvider;
import org.jboss.sbomer.core.features.sbom.config.OperationConfig;
import org.jboss.sbomer.core.features.sbom.config.PncBuildConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.DefaultProcessorConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.ErrataConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.GeneratorConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.ProcessorConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.ProductConfig;
import org.jboss.sbomer.core.features.sbom.config.runtime.RedHatProductProcessorConfig;
import org.jboss.sbomer.core.features.sbom.enums.GeneratorType;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SbomerConfigProviderTest {

    /**
     * Ensure default settings for generation.
     */
    @Test
    void shouldReturnDefaultGenerationConfig() {
        DefaultGenerationConfig defaultGenerationConfig = SbomerConfigProvider.getInstance()
                .getDefaultGenerationConfig();

        assertNotNull(defaultGenerationConfig);

        assertTrue(defaultGenerationConfig.isEnabled());
        assertEquals(GeneratorType.MAVEN_CYCLONEDX, defaultGenerationConfig.defaultGenerator());
        assertEquals(7, defaultGenerationConfig.generators().size());
        assertEquals(
                "--batch-mode -DschemaVersion=1.6 -Dcyclonedx.skipNotDeployed=false",
                defaultGenerationConfig.generators().get(GeneratorType.MAVEN_CYCLONEDX).defaultArgs());
        assertEquals(
                "--warn-on-missing-scm --legacy-scm-locator --hashes=false",
                defaultGenerationConfig.generators().get(GeneratorType.MAVEN_DOMINO).defaultArgs());
        assertEquals("-info", defaultGenerationConfig.generators().get(GeneratorType.GRADLE_CYCLONEDX).defaultArgs());
    }

    @Nested
    class ConfigAdjusting {

        private PncBuildConfig minimalRuntimeConfig() {
            List<ProcessorConfig> processors = new ArrayList<>();

            processors.add(
                    RedHatProductProcessorConfig.builder()
                            .withErrata(
                                    ErrataConfig.builder()
                                            .productName("CCCDDD")
                                            .productVersion("CCDD")
                                            .productVariant("CD")
                                            .build())
                            .build());

            ProductConfig productConfig = ProductConfig.builder()
                    .withGenerator(GeneratorConfig.builder().type(GeneratorType.MAVEN_CYCLONEDX).build())
                    .withProcessors(processors)

                    .build();

            return PncBuildConfig.builder().withBuildId("AABBCC").withProducts(List.of(productConfig)).build();
        }

        private OperationConfig minimalRuntimeOperationConfig() {
            List<ProcessorConfig> processors = new ArrayList<>();

            processors.add(
                    RedHatProductProcessorConfig.builder()
                            .withErrata(
                                    ErrataConfig.builder()
                                            .productName("CCCDDD")
                                            .productVersion("CCDD")
                                            .productVariant("CD")
                                            .build())
                            .build());

            ProductConfig productConfig = ProductConfig.builder()
                    .withGenerator(GeneratorConfig.builder().type(GeneratorType.CYCLONEDX_OPERATION).build())
                    .withProcessors(processors)

                    .build();

            return OperationConfig.builder().withOperationId("OPERATIONAABBCC").withProduct(productConfig).build();
        }

        @Test
        void shouldNotFailOnEmptyProducts() {
            PncBuildConfig config = PncBuildConfig.builder().withBuildId("ABCDEFG").build();
            assertDoesNotThrow(() -> SbomerConfigProvider.getInstance().adjust(config));
        }

        @Test
        void shouldProvideDefaultValues() {
            PncBuildConfig config = minimalRuntimeConfig();
            SbomerConfigProvider.getInstance().adjust(config);

            ProductConfig product = config.getProducts().get(0);

            assertEquals(2, product.getProcessors().size());
            assertInstanceOf(DefaultProcessorConfig.class, product.getProcessors().get(0));
            assertInstanceOf(RedHatProductProcessorConfig.class, product.getProcessors().get(1));
            assertEquals(GeneratorType.MAVEN_CYCLONEDX, product.getGenerator().getType());
            assertEquals("--batch-mode -DschemaVersion=1.6 -Dcyclonedx.skipNotDeployed=false", product.getGenerator().getArgs());
            assertEquals("2.9.0", product.getGenerator().getVersion());
        }

        @Test
        void shouldNotAdjustExplicitGeneratorVersion() {
            PncBuildConfig config = minimalRuntimeConfig();

            config.getProducts().get(0).getGenerator().setVersion("1.1.1");

            SbomerConfigProvider.getInstance().adjust(config);
            ProductConfig product = config.getProducts().get(0);

            assertEquals(2, product.getProcessors().size());
            assertInstanceOf(DefaultProcessorConfig.class, product.getProcessors().get(0));
            assertInstanceOf(RedHatProductProcessorConfig.class, product.getProcessors().get(1));
            assertEquals(GeneratorType.MAVEN_CYCLONEDX, product.getGenerator().getType());
            assertEquals("--batch-mode -DschemaVersion=1.6 -Dcyclonedx.skipNotDeployed=false", product.getGenerator().getArgs());
            assertEquals("1.1.1", product.getGenerator().getVersion());
        }

        @Test
        void shouldNotAdjustExplicitGeneratorArgs() {
            PncBuildConfig config = minimalRuntimeConfig();

            config.getProducts().get(0).getGenerator().setArgs("--custom-args");

            SbomerConfigProvider.getInstance().adjust(config);
            ProductConfig product = config.getProducts().get(0);

            assertEquals(2, product.getProcessors().size());
            assertInstanceOf(DefaultProcessorConfig.class, product.getProcessors().get(0));
            assertInstanceOf(RedHatProductProcessorConfig.class, product.getProcessors().get(1));
            assertEquals(GeneratorType.MAVEN_CYCLONEDX, product.getGenerator().getType());
            assertEquals("--custom-args", product.getGenerator().getArgs());
            assertEquals("2.9.0", product.getGenerator().getVersion());
        }

        @Test
        void shouldNotAddTwiceDefaultProcessor() {
            PncBuildConfig config = minimalRuntimeConfig();

            config.getProducts().get(0).getProcessors().add(0, DefaultProcessorConfig.builder().build());

            SbomerConfigProvider.getInstance().adjust(config);
            ProductConfig product = config.getProducts().get(0);

            assertEquals(2, product.getProcessors().size());
            assertInstanceOf(DefaultProcessorConfig.class, product.getProcessors().get(0));
            assertInstanceOf(RedHatProductProcessorConfig.class, product.getProcessors().get(1));
        }

        @Test
        void shouldNotAdjustExplicitGeneratorOperationArgs() {
            OperationConfig config = minimalRuntimeOperationConfig();

            config.getProduct().getGenerator().setArgs("--custom-args");

            SbomerConfigProvider.getInstance().adjust(config);
            ProductConfig product = config.getProduct();

            assertEquals(1, product.getProcessors().size());
            assertEquals(GeneratorType.CYCLONEDX_OPERATION, product.getGenerator().getType());
            assertNull(product.getGenerator().getArgs());
            assertNull(product.getGenerator().getVersion());
        }
    }
}
