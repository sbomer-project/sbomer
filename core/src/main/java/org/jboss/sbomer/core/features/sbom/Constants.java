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
package org.jboss.sbomer.core.features.sbom;

public class Constants {

    private Constants() {
        // This is a utility class
    }

    public static final String SBOMER_NAME = "SBOMer";
    public static final String SBOMER_LICENSE_ID = "Apache-2.0";
    public static final String SBOMER_LICENSE_URL = "https://www.apache.org/licenses/LICENSE-2.0.html";
    public static final String SBOMER_GIT_URL = "git@github.com:project-ncl/sbomer.git";
    public static final String SBOMER_WEBSITE = "https://github.com/project-ncl/sbomer";

    // Introduced as part of SBOMER-236
    public static final String REDHAT_PROPERTY_NAMESPACE_PREFIX = "redhat:";
    public static final String CONTAINER_PROPERTY_SYFT_PREFIX = "syft:";
    public static final String CONTAINER_PROPERTY_SYFT_REPLACEMENT_PREFIX = // REDHAT_PROPERTY_NAMESPACE_PREFIX +
            "sbomer:";
    public static final String PACKAGE_LANGUAGE = "package:language";
    public static final String CONTAINER_PROPERTY_PACKAGE_LANGUAGE_PREFIX = CONTAINER_PROPERTY_SYFT_REPLACEMENT_PREFIX
            + PACKAGE_LANGUAGE;
    public static final String CONTAINER_PROPERTY_PACKAGE_TYPE_PREFIX = CONTAINER_PROPERTY_SYFT_REPLACEMENT_PREFIX
            + "package:type";
    public static final String CONTAINER_PROPERTY_LOCATION_PATH_PREFIX = CONTAINER_PROPERTY_SYFT_REPLACEMENT_PREFIX
            + "location:0:path";
    public static final String CONTAINER_PROPERTY_METADATA_VIRTUALPATH_PREFIX = CONTAINER_PROPERTY_SYFT_REPLACEMENT_PREFIX
            + "metadata:virtualPath";
    public static final String IMAGE_LABELS = "image:labels";
    public static final String CONTAINER_PROPERTY_IMAGE_LABELS_PREFIX = CONTAINER_PROPERTY_SYFT_REPLACEMENT_PREFIX
            + IMAGE_LABELS;
    public static final String VERSION = ":version";
    public static final String CONTAINER_PROPERTY_IMAGE_LABEL_VERSION = CONTAINER_PROPERTY_IMAGE_LABELS_PREFIX
            + VERSION;
    public static final String RELEASE = ":release";
    public static final String CONTAINER_PROPERTY_IMAGE_LABEL_RELEASE = CONTAINER_PROPERTY_IMAGE_LABELS_PREFIX
            + RELEASE;
    public static final String CONTAINER_PROPERTY_IMAGE_LABEL_VENDOR = CONTAINER_PROPERTY_IMAGE_LABELS_PREFIX
            + ":vendor";
    public static final String CONTAINER_PROPERTY_IMAGE_LABEL_MANTAINER = CONTAINER_PROPERTY_IMAGE_LABELS_PREFIX
            + ":maintainer";
    public static final String CONTAINER_PROPERTY_IMAGE_LABEL_NAME = CONTAINER_PROPERTY_IMAGE_LABELS_PREFIX + ":name";
    public static final String COM_REDHAT_COMPONENT = ":com.redhat.component";
    public static final String CONTAINER_PROPERTY_IMAGE_LABEL_COMPONENT = CONTAINER_PROPERTY_IMAGE_LABELS_PREFIX
            + COM_REDHAT_COMPONENT;
    public static final String CONTAINER_PROPERTY_IMAGE_LABEL_ARCHITECTURE = CONTAINER_PROPERTY_IMAGE_LABELS_PREFIX
            + ":architecture";
    public static final String CONTAINER_PROPERTY_ADVISORY_ID = REDHAT_PROPERTY_NAMESPACE_PREFIX + "advisory_id";

    public static final String SBOM_RED_HAT_DELIVERABLE_URL = REDHAT_PROPERTY_NAMESPACE_PREFIX + "deliverable-url";
    public static final String SBOM_RED_HAT_DELIVERABLE_CHECKSUM = REDHAT_PROPERTY_NAMESPACE_PREFIX
            + "deliverable-checksum";

    public static final String SBOM_RED_HAT_PNC_OPERATION_ID = "pnc-operation-id";
    public static final String SBOM_RED_HAT_PNC_BUILD_ID = "pnc-build-id";
    public static final String SBOM_RED_HAT_PNC_ARTIFACT_ID = "pnc-artifact-id";
    public static final String SBOM_RED_HAT_BREW_BUILD_ID = "brew-build-id";
    public static final String SBOM_RED_HAT_PUBLIC_URL = "public-url";
    public static final String SBOM_RED_HAT_ORIGIN_URL = "origin-url";
    public static final String SBOM_RED_HAT_BUILD_SYSTEM = "build-system";
    public static final String SBOM_RED_HAT_SCM_URL = "scm-url";
    public static final String SBOM_RED_HAT_SCM_REVISION = "scm-revision";
    public static final String SBOM_RED_HAT_SCM_TAG = "scm-tag";
    public static final String SBOM_RED_HAT_SCM_EXTERNAL_URL = "scm-external-url";
    public static final String SBOM_RED_HAT_ENVIRONMENT_IMAGE = "pnc-environment-image";

    public static final String PNC_BUILD_SYSTEM = "PNC";
    public static final String BREW_BUILD_SYSTEM = "BREW";

    public static final String DISTRIBUTION = "Red Hat distribution";
    public static final String PUBLISHER = "Red Hat";
    public static final String SUPPLIER_NAME = "Red Hat";
    public static final String SUPPLIER_URL = "https://www.redhat.com";
    public static final String MRRC_URL = "https://maven.repository.redhat.com/ga/";

    public static final String PROPERTY_ERRATA_PRODUCT_NAME = "errata-tool-product-name";
    public static final String PROPERTY_ERRATA_PRODUCT_VERSION = "errata-tool-product-version";
    public static final String PROPERTY_ERRATA_PRODUCT_VARIANT = "errata-tool-product-variant";

    public static final String BUILD_ATTRIBUTES_BREW_BUILD_VERSION = "BREW_BUILD_VERSION";
    public static final String BUILD_ATTRIBUTES_BREW_BUILD_NAME = "BREW_BUILD_NAME";
    public static final String GRADLE_MAJOR_VERSION_COMMAND_PREFIX = "GRADLE_MAJOR_VERSION=";
    public static final String GRADLE_PLUGIN_VERSION_ENV_VARIABLE = "PLUGIN_VERSION";

    public static final String SBT_COMPONENT_DOT_SEPARATOR = "_____";
    public static final String SBT_COMPONENT_COORDINATES_SEPARATOR = "_______";

    /**
     * The label name that identifies the particular Sbom resource.
     */
    public static final String TEKTON_LABEL_SBOM_ID = "sbomer.jboss.org/sbom-id";

    /**
     * The label name that identifies the particular Sbom build id.
     */
    public static final String TEKTON_LABEL_SBOM_BUILD_ID = "sbomer.jboss.org/sbom-build-id";

    /**
     * Default Kubernetes label: app.kubernetes.io/part-of
     */
    public static final String TEKTON_LABEL_NAME_APP_PART_OF = "app.kubernetes.io/part-of";

    /**
     * Value for the default Kubernetes label: app.kubernetes.io/part-of: sbomer
     */
    public static final String TEKTON_LABEL_VALUE_APP_PART_OF = "sbomer";

    /**
     * The suffix which is used in a Task Run name to identify the number of retry attempts
     */
    public static final String TEKTON_TASK_RUN_NAME_SUFFIX_RETRY_ATTEMPT = "retry";

}
