#!/bin/bash

#@author Daniel Andrzejewski

#set -x

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

echo "manifests = ${manifests}"

echo "===START manifests response"

curl -sv ${manifests}

echo "===END manifests response"

schema_version=$(curl -s "http://${REGISTRY}/v2/${IMAGE}/manifests/${TAG}" | jq -r '.schemaVersion')

if [ -z "${schema_version}" ] ; then
  echo "Cannot get schema version from ${REGISTRY} registry!"
  exit 2
fi

if [ "${schema_version}" -ne "1" ] && [ "${schema_version}" -ne "2" ] ; then
  echo "Schema '${schema_version}' not supported!"
  exit 2
fi

# skip a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4 layer, which is an "empty layer" entry

for layer in $(curl -s ${manifests} | jq -r '.fsLayers[].blobSum' | grep -v 'a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4'); do

  echo "Indexing layer ${layer} ==> {\"Layer\":{\"Name\":\"${layer}\",\"Path\":\"http://${REGISTRY}/v2/${IMAGE}/blobs/${layer}\",\"Format\":\"Docker\"}}"

  # let CLAIR analyze docker image composed by only one "scannable" layer
  clair_response=$(curl -s -X POST http://${CLAIR}/v1/layers -d "{\"Layer\":{\"Name\":\"${layer}\",\"Path\":\"http://${REGISTRY}/v2/${IMAGE}/blobs/${layer}\",\"Format\":\"Docker\"}}")

  no_layer=$(echo ${clair_response} | grep "could not find layer" | wc -l)

  if [ "$no_layer" -eq "1" ] ; then
    echo "MESSAGE: could not find layer"
    continue
  fi

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
