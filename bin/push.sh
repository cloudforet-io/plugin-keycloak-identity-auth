#!/usr/bin/env bash
# How to upload
DEFAULT=0.1
VER=${1:-$DEFAULT}
./build.sh ${VER}
docker push pyengine/plugin-keycloak-identity-auth:${VER}
