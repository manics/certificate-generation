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
# GoDaddy timestamp server (set to empty to disable)
TIMESTAMP_SERVER=http://tsa.starfieldtech.com
TIMESTAMP_SERVER=

jarsign() {
    JAR="$1"
    echo "Signing $JAR"
    if [ -n "$TIMESTAMP_SERVER" ]; then
        jarsigner -keystore "$JAVA_KEYSTORE" -storepass "$JAVA_KEYSTORE_PASSWORD" -keypass "$JAVA_PRIVKEY_PASSWORD" -tsa "$TIMESTAMP_SERVER" "$JAR" "$ALIAS"
    else
        jarsigner -keystore "$JAVA_KEYSTORE" -storepass "$JAVA_KEYSTORE_PASSWORD" -keypass "$JAVA_PRIVKEY_PASSWORD" "$JAR" "$ALIAS"
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
    unzip "$SERVERZIP"
fi

for jar in "$SERVER"/lib/insight/*.jar; do
    jarsign "$jar"
done

if [ -n "$SERVERZIP" ]; then
    mv "$SERVERZIP" "$SERVERZIP".unsigned
    zip -r "$SERVER-jarsigned.zip" "$SERVER"
    md5sum "$SERVER-jarsigned.zip" > "$SERVER-jarsigned.zip.md5"
fi

rm -r "$SERVER"
