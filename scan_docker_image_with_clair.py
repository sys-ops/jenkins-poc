#!/usr/bin/env python
#/usr/bin/env python3
'''
@author: Daniel Andrzejewski

@file: scan_docker_image_with_clair.py
'''

import argparse
import json
import requests
import sys

OK = 0
WARN = 1
CRIT = 2
MAX_CONNECTION_TIMEOUT = 10

def main():
    argp = argparse.ArgumentParser(description='Scan docker image using CLAIR', formatter_class=argparse.RawTextHelpFormatter)

    # command line options (arguments)
    argp.add_argument('-c', '--clair', dest='clair', type=str, metavar='STRING',
                      help='Clair URL', required=False, default='localhost:6060')
    argp.add_argument('-r', '--registry', dest='registry', type=str, metavar='STRING',
                      help='Docker Registry URL', required=False, default='localhost:5000')
    argp.add_argument('-i', '--image-name', dest='image', type=str, metavar='STRING',
                      help='Docker image name', required=False, default='nginx')
    argp.add_argument('-t', '--image-tag', dest='tag', type=str, metavar='STRING',
                      help='Docker image tag', required=False, default='1.9.1')
    argp.add_argument('-l', '--level', dest='level', type=str, metavar='STRING',
                      help='Minimum level of severity', required=False, default='Critical',
                      choices=['Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical'])
    argp.add_argument('-v', '--verbose', dest='verbose', default=False, action='store_true')

    # get arguments to 'args'
    args = argp.parse_args()

    # copy arguments to variables
    clair = args.clair
    registry = args.registry
    image = args.image
    tag = args.tag
    level = args.level
    verbose = args.verbose

    manifests='http://{0}/v2/{1}/manifests/{2}'.format(registry, image, tag)

    try:
        response = requests.get(manifests)
    except requests.RequestException as e:
        print('ERROR: ' + str(e))
        return CRIT

    if response.status_code != 200:
        print('ERROR: response from {0} docker registry = {1}'.format(response.status_code, registry))
        return CRIT

    data = json.loads(response.text)

    if 'schemaVersion' in data:
        print('Docker Registry schema version = {0}\n'.format(data['schemaVersion']))
    else:
        print('ERROR: Cannot get schema version from {0} registry!'.format(registry))
        return CRIT

    if 'fsLayers' not in data:
        print('ERROR: Missing fsLayers in the response from {0} registry!'.format(registry))
        return CRIT

    # get unique layers
    # skip the "empty" layer a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    layers = set()

    for elem in data['fsLayers']:
        blob_sum = elem['blobSum']

        if 'a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4' in blob_sum:
            continue
        layers.add(blob_sum)

    if len(layers) == 0:
        print('DONE: No unique layers to scan')
        return OK

    print('Analysing {0} layers\n'.format(len(layers)))

    all_vulnerabilities = {}
    severities = {}

    # perform indexing of layers by Clair
    for layer in layers:
        payload = {"Layer": {"Name": "{0}".format(layer), "Path": "http://{0}/v2/{1}/blobs/{2}".format(registry, image, tag), "Format": "Docker"}}

        if verbose:
            print('\tIndexing new layer {0}\n'.format(layer))

        try:
            response = requests.post('http://{0}/v1/layers'.format(clair), json=payload)
        except requests.RequestException as e:
            print('ERROR: ' + str(e))
            return CRIT

        if verbose and 'could not find layer' in response.text:
            print('MESSAGE: could not find layer!\n')
            continue

        if verbose:
            print(response.text)

        # get a result of found vulnerabilities in the layer
        try:
            response = requests.get('http://{0}/v1/layers/{1}?vulnerabilities'.format(clair, layer))
        except requests.RequestException as e:
            print('ERROR: ' + str(e))
            return CRIT

        vulnerabilities = json.loads(response.text)

        if 'Error' in vulnerabilities:
            print(vulnerabilities)
            continue

        if 'Features' in vulnerabilities['Layer'].keys():
            for elem in vulnerabilities['Layer']['Features']:
                if 'Vulnerabilities' in elem:
                    for vulnerability in elem['Vulnerabilities']:
                        name = vulnerability['Name']
                        description = ''
                        link = ''
                        severity = ''
                        if 'Description' in vulnerability:
                            description = vulnerability['Description']
                        if 'Link' in vulnerability:
                            link = vulnerability['Link']
                        if 'Severity' in vulnerability:
                            severity = vulnerability['Severity']

                        if name not in all_vulnerabilities:
                            all_vulnerabilities[name] = {}
                            all_vulnerabilities[name]['Description'] = description
                            all_vulnerabilities[name]['Link'] = link
                            all_vulnerabilities[name]['Severity'] = severity

                        # count all vulnerabilities by the severity level
                        if severity in severities:
                            severities[severity] += 1
                        else:
                            severities[severity] = 1

    minimum_level = False

    for severity in ['Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical']:
        if level == severity and minimum_level == False:
            minimum_level = True

        if minimum_level == True:
            for vulnerability in all_vulnerabilities:
                if severity != all_vulnerabilities[vulnerability]['Severity']:
                    continue

                print('{0}: [{1}]\n'.format(vulnerability, severity))
                print('Description: {0}'.format(all_vulnerabilities[vulnerability]['Description']))
                print('Link: {0}'.format(all_vulnerabilities[vulnerability]['Link']))
                print('-----------------------------------------\n')

    # print all vulnerabilities by the severity level
    for severity in ['Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical']:
        if severity in severities:
            print('{0}: {1}'.format(severity, severities[severity]))


    return OK


if __name__ == '__main__':
    sys.exit(main())
