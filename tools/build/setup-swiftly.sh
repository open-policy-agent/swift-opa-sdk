#!/bin/bash

# This script is a slightly stripped down version of the 'prep-gh-action.sh'
# script from swiftlang/swiftly. The main differences are around sudo
# handling, and we do not install development dependencies like libarchive.

if [[ "$(uname -s)" == "Linux" ]]; then
    # Install the basic utilities depending on the type of Linux distribution
    sudo apt-get --help && sudo apt-get update && sudo TZ=Etc/UTC apt-get -y install curl make gpg tzdata
    sudo yum --help && (curl --help && sudo yum -y install curl) && sudo yum install make gpg
fi

set -e

while [ $# -ne 0 ]; do
    arg="$1"
    case "$arg" in
        --install-swiftly)
            installSwiftly=true
            ;;
        --swift-snapshot)
            swiftSnapshot="$2"
            shift;
            ;;
        *)
            ;;
    esac
    shift
done

if [ "$installSwiftly" == true ]; then
    echo "Installing swiftly"

    if [[ "$(uname -s)" == "Linux" ]]; then
        curl -O https://download.swift.org/swiftly/linux/swiftly-$(uname -m).tar.gz && tar zxf swiftly-*.tar.gz && ./swiftly init -y --skip-install
        . "/home/runner/.local/share/swiftly/env.sh"
    else
        export SWIFTLY_HOME_DIR="$(pwd)/swiftly-bootstrap"
        export SWIFTLY_BIN_DIR="$SWIFTLY_HOME_DIR/bin"
        export SWIFTLY_TOOLCHAINS_DIR="$SWIFTLY_HOME_DIR/toolchains"

        curl -O https://download.swift.org/swiftly/darwin/swiftly.pkg && pkgutil --check-signature swiftly.pkg && pkgutil --verbose --expand swiftly.pkg "${SWIFTLY_HOME_DIR}" && tar -C "${SWIFTLY_HOME_DIR}" -xvf "${SWIFTLY_HOME_DIR}"/swiftly-*/Payload && "$SWIFTLY_HOME_DIR/bin/swiftly" init -y --skip-install

        . "$SWIFTLY_HOME_DIR/env.sh"
    fi

    hash -r

    if [ -n "$GITHUB_ENV" ]; then
        echo "Updating GitHub environment"
        echo "PATH=$PATH" >> "$GITHUB_ENV" && echo "SWIFTLY_HOME_DIR=$SWIFTLY_HOME_DIR" >> "$GITHUB_ENV" && echo "SWIFTLY_BIN_DIR=$SWIFTLY_BIN_DIR" >> "$GITHUB_ENV" && echo "SWIFTLY_TOOLCHAINS_DIR=$SWIFTLY_TOOLCHAINS_DIR" >> "$GITHUB_ENV"
    fi

    selector=()
    runSelector=()

    if [ "$swiftSnapshot" != "" ]; then
        echo "Installing latest $swiftSnapshot-snapshot toolchain"
        selector=("$swiftSnapshot-snapshot")
        runSelector=("+$swiftSnapshot-snapshot")
    elif [ -f .swift-version ]; then
        echo "Installing selected swift toolchain from .swift-version file"
        selector=()
        runSelector=()
    else
        echo "Installing latest toolchain"
        selector=("latest")
        runSelector=("+latest")
    fi

    swiftly install --post-install-file=post-install.sh "${selector[@]}"

    if [ -f post-install.sh ]; then
        echo "Performing swift toolchain post-installation"
        chmod u+x post-install.sh && sudo ./post-install.sh
    fi

    echo "Displaying swift version"
    swiftly run "${runSelector[@]}" swift --version
fi