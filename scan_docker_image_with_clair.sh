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

#curl http://centos:5000/v2/debian/manifests/9.5

#for blobsum in $(curl -s http://${REGISTRY}/v2/${IMAGE}/manifests/${TAG} | grep blobSum | awk '{print $2}' | sed 's/"//g' | cut -d':' -f2); do

resp=''
high_vulnerabilities_found=0

echo "http://${REGISTRY}/v2/${IMAGE}/manifests/${TAG}"

for blobsum in $(curl -s http://${REGISTRY}/v2/${IMAGE}/manifests/${TAG} | grep blobSum | cut -d'"' -f4); do

  echo $blobsum

  #curl "http://${CLAIR}/v1/layers/${blobsum}?vulnerabilities" | jq | grep -B 5 -A 17 'Severity": "High'
  curl "http://${CLAIR}/v1/layers/${blobsum}?vulnerabilities" | jq | grep -B 5 -A 17 'Severity": "'

  resp_count=$(curl -s "http://${CLAIR}/v1/layers/${blobsum}?vulnerabilities" | jq | grep -B 5 -A 17 'Severity": "High' | wc -c)

  if [ "${resp_count}" -gt 10 ] ; then
    echo -e "\n================================================================="
    echo -e "                High vulnerabilities found in ${IMAGE}:${TAG}"
    echo -e "=================================================================\n"

    high_vulnerabilities_found=1
  fi

done
