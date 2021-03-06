#!/bin/bash
# Sign all jars required by OMERO.server webstart

set -eu

if [ $# -ne 5 ]; then
    echo "USAGE: `basename $0` keystore.jks keystore-password private-key-password alias server_directory|server.zip"
    exit 2
fi

JAVA_KEYSTORE="$1"
JAVA_KEYSTORE_PASSWORD="$2"
JAVA_PRIVKEY_PASSWORD="$3"
ALIAS="$4"
SERVER="$5"

# GoDaddy timestamp server
TIMESTAMP_SERVER=http://tsa.starfieldtech.com
# The timestamp server may be throttled, if this happens try adding a delay
# and retry
TIMESTAMP_SERVER_DELAY=2
FAILURE_RETRIES=3
# Uncomment to disable
#TIMESTAMP_SERVER=

jarsign() {
    FAILURES=0
    JAR="$1"
    echo "Signing $JAR"
    if [ -n "$TIMESTAMP_SERVER" ]; then
        while [ $FAILURES -lt $FAILURE_RETRIES ]; do
            jarsigner -keystore "$JAVA_KEYSTORE" \
                -storepass "$JAVA_KEYSTORE_PASSWORD" \
                -keypass "$JAVA_PRIVKEY_PASSWORD" \
                -tsa "$TIMESTAMP_SERVER" \
                "$JAR" "$ALIAS" \
                && break || let FAILURES+=1
            if [ $FAILURES -ge $FAILURE_RETRIES ]; then
                echo "ERROR: Failed to sign $JAR after $FAILURES attempts"
                exit 3
            fi
            sleep "$TIMESTAMP_SERVER_DELAY"
        done
    else
        jarsigner -keystore "$JAVA_KEYSTORE" \
            -storepass "$JAVA_KEYSTORE_PASSWORD" \
            -keypass "$JAVA_PRIVKEY_PASSWORD" \
            "$JAR" "$ALIAS"
    fi
}

SERVERZIP=
if [ -f "$SERVER" ]; then
    SERVERZIP="$SERVER"
    SERVER="`basename ${SERVER%.zip}`"
    if [ -e "$SERVER" ]; then
        echo "ERROR: $SERVER already exists, delete this file/directory"
        exit 2
    fi
    SERVERZIPOUT="$SERVER-jarsigned.zip"
    if [ -e "$SERVERZIPOUT" ]; then
        echo "ERROR: $SERVERZIPOUT already exists, delete this file/directory"
        exit 2
    fi
    unzip "$SERVERZIP"
fi

for jar in "$SERVER"/lib/insight/*.jar; do
    jarsign "$jar"
done

if [ -n "$SERVERZIP" ]; then
    zip -r "$SERVERZIPOUT" "$SERVER"
    md5sum "$SERVERZIPOUT" > "$SERVERZIPOUT.md5"
    rm -r "$SERVER"
fi
