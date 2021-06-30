#!/bin/bash

#@author daniel.andrzejewski

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

resp=''
high_vulnerabilities_found=0

echo "http://${REGISTRY}/v2/${IMAGE}/manifests/${TAG}"

for blobsum in $(curl -s http://${REGISTRY}/v2/${IMAGE}/manifests/${TAG} | grep blobSum | cut -d'"' -f4); do

  echo "Indexing blob ${blobsum} ==> {\"Layer\":{\"Name\":\"${blobsum}\",\"Path\":\"http://${REGISTRY}/v2/${IMAGE}/blobs/${blobsum}\",\"Format\":\"Docker\"}}"

  #Step 4 Now let’s tell Clair to analyze our docker image composed by only one “scannable” layer.
  curl -s -X POST http://${CLAIR}/v1/layers -d "{\"Layer\":{\"Name\":\"${blobsum}\",\"Path\":\"http://${REGISTRY}/v2/${IMAGE}/blobs/${blobsum}\",\"Format\":\"Docker\"}}"

  # Step 5 get a result of found vulnerabilities in the layer by calling the endpoint:
  # GET http://centos:6060/v1/layers/sha256:bc9ab73e5b14b9fbd3687a4d8c1f1360533d6ee9ffc3f5ecc6630794b40257b7?features&vulnerabilitie
  echo "Getting results of found vulnerabilities in the layer ${blobsum}"

  curl -s "http://${CLAIR}/v1/layers/${blobsum}?vulnerabilities" | jq | grep -B 5 -A 17 'Severity": "'

  resp_count=$(curl -s "http://${CLAIR}/v1/layers/${blobsum}?vulnerabilities" | jq | grep -B 5 -A 17 'Severity": "High' | wc -c)

  if [ "${resp_count}" -gt 10 ] ; then
    high_vulnerabilities_found=1
  fi

done

if [ "${high_vulnerabilities_found}" -eq 1 ] ; then
  echo -e "\n================================================================="
  echo -e "                High vulnerabilities found in ${IMAGE}:${TAG}"
  echo -e "=================================================================\n"
fi
