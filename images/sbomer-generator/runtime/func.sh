#!/usr/bin/env bash
#
# JBoss, Home of Professional Open Source.
# Copyright 2023 Red Hat, Inc., and individual contributors
# as indicated by the @author tags.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# List all available Temurin Java versions for a given major release.
function available_java_versions() {
    local version=${1}
    curl -s "https://api.sdkman.io/2/candidates/java/Linuxx64/versions/all" | tr ',' '\n' | grep -- '-tem$' | grep "^${version}\."
}

# Find the latest version of Temurin Java for a given major release.
function latest_java_version() {
    available_java_versions "${1}" | sort -V | tail -n 1
}

function retry() {
    max_attempts=3
    result=0
    count=1

    while [[ "${count}" -le "${max_attempts}" ]]; do
        result=0
        "${@}" || result="${?}"
        if [[ $result -eq 0 ]]; then return 0; fi
        echo "Command failed, will retry..."
        count="$((count + 1))"
        sleep 10
        echo "Retrying..."
    done

    echo "Command failed despite we tried it to run it ${max_attempts} times"
    exit 1
}

function install_java() {
    local version=${1}
    local certs_path="/etc/pki/ca-trust/source/anchors"

    sdk install java "${version}"
    # Make an alias for major version
    sdk install java ${version%%.*} "$(sdk home java ${version} | tail -n 1)"

    # Of course JDK 8 uses different paths and the keytool command does not have the '-cacerts' flag
    local ca_keystore_path="$HOME/.sdkman/candidates/java/${version}/jre/lib/security/cacerts"

    if [ ! -f "$ca_keystore_path" ]; then
        ca_keystore_path="$HOME/.sdkman/candidates/java/${version}/lib/security/cacerts"
    fi

    for cert in "2015-IT-Root-CA" "2022-IT-Root-CA"; do
        keytool -delete -alias "${cert}" -keystore "${ca_keystore_path}" -noprompt -storepass changeit || true
        keytool -import -trustcacerts -alias "${cert}" -file "${certs_path}/${cert}.pem" -keystore "$ca_keystore_path" -noprompt -storepass changeit
    done
}

function install_major_java() {
    local version=${1}
    local java_version
    java_version=$(latest_java_version "${version}")

    if [[ -z "${java_version}" ]]; then
        echo "Could not find a Temurin release for Java ${version}" >&2
        return 1
    fi

    install_java "${java_version}"
}

function install_sdk() {
    curl -s "https://get.sdkman.io" | bash
    echo "sdkman_auto_answer=true" >.sdkman/etc/config
}

function install_nvm() {
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
}

function install_nodejs() {
    cat <<'EOF' >>"$HOME/.npmrc"
loglevel=info
maxsockets=80
fetch-retries=10
fetch-retry-mintimeout=60000
EOF

    nvm install "${1}" --no-use
    echo ${1} >"$HOME/.nvmrc"
}

function install_yarn() {
    npm install --global yarn
}

function install_sbt() {
    local version=${1}
    sdk install sbt "${version}"
}

# Installs Domino.
function install_domino() {
    echo "> Installing Domino CycloneDX SBOM generator version '${1}'"

    # Ensure the target directory exists
    mkdir -p "${SBOMER_DOMINO_DIR}"

    curl -s -L https://github.com/quarkusio/quarkus-platform-bom-generator/releases/download/${1}/domino.jar -o ${SBOMER_DOMINO_DIR}/domino-${1}.jar

    echo "Domino installed!"
}

function install_npm_cyclonedx() {
    echo "Installing @cyclonedx/cyclonedx-npm NPM package version '${1}'"
    npm install --global "@cyclonedx/cyclonedx-npm@${1}"
    echo "NPM package @cyclonedx/cyclonedx-npm installed!"
}
