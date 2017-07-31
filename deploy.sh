#!/bin/bash
BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
USAGE="Usage: deploy [all|generate|validate] [all|java|proxy|sharedflow]"
ORG="org name"
ENV="env name"

if [ -z "$1" ]; then
	echo $USAGE
	exit 1
fi

if [ -z "$2" ]; then
	set -- "${@:1}" "all"
fi
set -eu

if [ "$1" = "generate" ] || [ "$1" = "all" ] ; then
	if [ "$2" = "java" ] || [ "$2" = "all" ] ; then
		cd $BASEDIR/jwt-generate-callout
		gradle clean
		gradle build
	fi
	if [ "$2" = "proxy" ] || [ "$2" = "all" ] ; then
		cd $BASEDIR
		rm jwt-generate-api/apiproxy/resources/java/*
		cp jwt-generate-callout/build/libs/edge-jwt-generate.jar jwt-generate-api/apiproxy/resources/java/
		cp jwt-generate-callout/lib/jose4j-0.5.7.jar jwt-generate-api/apiproxy/resources/java/

		apigeetool deployproxy -u $EDGE_USERNAME -p $EDGE_PASSWORD -o $ORG -e $ENV -n jwt-generate-api -d ./jwt-generate-api
	fi
fi

if [ "$1" = "validate" ] || [ "$1" = "all" ] ; then
	if [ "$2" = "java" ] || [ "$2" = "all" ] ; then
		cd $BASEDIR/jwt-validate-callout
		gradle clean
		gradle build
	fi
	if [ "$2" = "sharedflow" ] || [ "$2" = "all" ] ; then
		cd $BASEDIR
		rm jwt-validate-sf/sharedflowbundle/resources/java/*
		cp jwt-validate-callout/build/libs/edge-jwt-validate.jar jwt-validate-sf/sharedflowbundle/resources/java/
		cp jwt-validate-callout/lib/jose4j-0.5.7.jar jwt-validate-sf/sharedflowbundle/resources/java/

		apigeetool deploySharedflow -u $EDGE_USERNAME -p $EDGE_PASSWORD -o $ORG -e $ENV -n jwt-validate-sf -d ./jwt-validate-sf
	fi
	if [ "$2" = "proxy" ] || [ "$2" = "all" ] ; then
		cd $BASEDIR
		apigeetool deployproxy -u $EDGE_USERNAME -p $EDGE_PASSWORD -o $ORG -e $ENV -n jwt-validate-api -d ./jwt-validate-api
	fi
fi
