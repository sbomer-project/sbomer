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
package org.jboss.sbomer.cli.feature.sbom.adjuster;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.component.evidence.Identity;
import org.cyclonedx.model.component.evidence.Identity.Field;
import org.jboss.pnc.common.Strings;
import org.jboss.sbomer.cli.feature.sbom.utils.UriValidator;
import org.jboss.sbomer.core.features.sbom.utils.SbomUtils;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class AbstractAdjuster implements Adjuster {

    protected void cleanupComponents(Bom bom) {
        // Cleanup main component
        cleanupComponent(bom.getMetadata().getComponent());
        cleanupComponents(bom.getMetadata().getComponent().getComponents());

        // ...and all other components
        cleanupComponents(bom.getComponents());
    }

    /**
     * Adjusts all provided {@link Component}s according to our standards.
     *
     * @param components the components
     */
    private void cleanupComponents(List<Component> components) {
        if (components == null) {
            return;
        }

        for (Component component : components) {
            cleanupComponent(component);
            cleanupComponents(component.getComponents());
        }
    }

    protected void addMissingMetadataSupplier(Bom bom) {
        SbomUtils.addMissingMetadataSupplier(bom);
    }

    protected static void addMissingSerialNumber(Bom bom) {
        SbomUtils.addMissingSerialNumber(bom);
    }

    /**
     * Adjusts the provided {@link Component} according to our standards.
     *
     * @param component the component
     */
    abstract void cleanupComponent(Component component);

    protected void cleanupExternalReferences(List<ExternalReference> externalReferences) {
        if (externalReferences != null) {
            externalReferences.removeIf(er -> !Strings.isEmpty(er.getUrl()) && !UriValidator.isUriValid(er.getUrl()));
        }
    }

    /**
     * <p>
     * Ensures that the main component is present in the {@link Bom#getComponents()} list.
     * </p>
     *
     * <p>
     * At the same time it cleans up the main component available in the {@link Metadata#getComponent()}.
     * </p>
     *
     * @param bom the manifest to adjust
     */
    protected void adjustMainComponent(Bom bom) {
        Component mainComponent = bom.getMetadata().getComponent();
        // Skip main component if it doesn't exist or has already been adjusted
        if (mainComponent == null || mainComponent.getBomRef() == null) {
            return;
        }

        // Create a new component out of the current main component which will replace it.
        Component metadataComponent = new Component();
        metadataComponent.setType(mainComponent.getType());
        metadataComponent.setName(mainComponent.getName());
        metadataComponent.setPurl(mainComponent.getPurl());
        metadataComponent.setHashes(mainComponent.getHashes());

        Evidence mainEvidence = mainComponent.getEvidence();
        // Copy any additional purls if they exist
        if (mainEvidence != null && mainEvidence.getIdentities() != null && !mainEvidence.getIdentities().isEmpty()) {
            List<Identity> purlIdentities = mainEvidence.getIdentities()
                    .stream()
                    .filter(identity -> Field.PURL.equals(identity.getField()))
                    .collect(Collectors.toList());
            if (!purlIdentities.isEmpty()) {
                Evidence metadataEvidence = new Evidence();
                metadataEvidence.setIdentities(purlIdentities);
                metadataComponent.setEvidence(metadataEvidence);
            }
        }

        // If its generic purl then try and aquire a version from the filename
        SbomUtils.setPurlVersionFromGeneric(metadataComponent);

        // Set main component
        bom.getMetadata().setComponent(metadataComponent);

        List<Component> components = bom.getComponents();

        if (components == null) {
            components = new ArrayList<>();
            bom.setComponents(components);
        }

        // Set the main component
        if (components.isEmpty() || !mainComponent.getBomRef().equals(components.get(0).getBomRef())) {
            components.add(0, mainComponent);
        }
    }
}
