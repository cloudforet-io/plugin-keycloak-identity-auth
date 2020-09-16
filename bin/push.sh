#!/usr/bin/env bash
# How to upload
./build.sh
docker push pyengine/keycloak-oidc:1.1
docker push spaceone/keycloak-oidc:1.1
