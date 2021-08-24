#! /bin/bash
# Build a docker image
DEFAUKT=0.1
VER=${1:-$DEFAULT}
cd ..
docker build -t pyengine/plugin-keycloak-identity-auth .
docker tag pyengine/plugin-keycloak-identity-auth pyengine/plugin-keycloak-identity-auth:${VER}
