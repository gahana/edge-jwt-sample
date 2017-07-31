#!/bin/bash
set -eu

BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $BASEDIR
export CLASSPATH="./lib/jose4j-0.5.7.jar:./lib/slf4j-api-1.7.21.jar:./lib/slf4j-nop-1.8.0-alpha2.jar:."

javac JWTUtil.java
java JWTUtil
