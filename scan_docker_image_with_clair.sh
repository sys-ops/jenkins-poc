#!/bin/bash

#@author Daniel Andrzejewski

set -x

if [ $# -ne 4 ]
then
  echo "Usage: `basename $0` [docker registry url] [image name] [image tag] [clair url]"
  exit 1
fi

REGISTRY=$1
IMAGE=$2
TAG=$3
CLAIR=$4

high_vulnerabilities_found=0

manifests="http://${REGISTRY}/v2/${IMAGE}/manifests/${TAG}"

for layer in $(curl -s ${manifests} | grep blobSum | cut -d'"' -f4); do

  echo "Indexing layer ${layer} ==> {\"Layer\":{\"Name\":\"${layer}\",\"Path\":\"http://${REGISTRY}/v2/${IMAGE}/blobs/${layer}\",\"Format\":\"Docker\"}}"

  # let CLAIR analyze docker image composed by only one "scannable" layer
  curl -s -X POST http://${CLAIR}/v1/layers -d "{\"Layer\":{\"Name\":\"${layer}\",\"Path\":\"http://${REGISTRY}/v2/${IMAGE}/blobs/${layer}\",\"Format\":\"Docker\"}}"

  # get a result of found vulnerabilities in the layer by calling the endpoint http://${CLAIR}/v1/layers/${layer}
  echo "Getting results of found vulnerabilities in the layer ${layer}"

  curl -s "http://${CLAIR}/v1/layers/${layer}?vulnerabilities" | jq | grep -B 5 -A 17 'Severity": "'

  resp_count=$(curl -s "http://${CLAIR}/v1/layers/${layer}?vulnerabilities" | jq | grep -B 5 -A 17 'Severity": "High' | wc -c)

  if [ "${resp_count}" -gt 10 ] ; then
    high_vulnerabilities_found=1
  fi

done

if [ "${high_vulnerabilities_found}" -eq 1 ] ; then
  echo -e "\n================================================================="
  echo -e "                High vulnerabilities found in ${IMAGE}:${TAG}"
  echo -e "=================================================================\n"
fi
