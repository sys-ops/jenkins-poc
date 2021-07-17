#!/bin/bash

#@author Daniel Andrzejewski

#set -x

if [ $# -ne 2 ]
then
  echo "Usage: `basename $0` [docker registry url] [clair url]"
  exit 1
fi

REGISTRY=$1
CLAIR=$2

for IMAGE in $(curl -s ${REGISTRY}/v2/_catalog | jq -r '.repositories[]') ; do
  for TAG in $(curl -s ${REGISTRY}/v2/${IMAGE}/tags/list | jq -r '.tags[]') ; do
    echo -e "--------------------------------------------------------\n"
    echo -e "Scanning ${IMAGE}:${TAG} image\n"
    ./scan_docker_image_with_clair.py --clair ${CLAIR} --registry ${REGISTRY} --image-name ${IMAGE} --image-tag ${TAG} --level Low --verbose
  done
done
