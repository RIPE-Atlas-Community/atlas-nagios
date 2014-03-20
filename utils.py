import sys
import time
import argparse
import requests
import json
import pprint

from measurements import *

def get_response(url):
    '''Fetch a Json Object from url'''
    headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
            }
    try:
        request = requests.get(url,headers=headers)
        request.raise_for_status()
    except requests.exceptions.RequestException as error:
        print '''Unknown: Fatal error when reading request: %s''' % error
        sys.exit(3)

    if request.status_code in [200, 201, 202]:
        return request.json()
    else:
        print '''Unexpected non-fatal status code: %s''' % request.status_code
        sys.exit(3)


def get_measurements(measurement_id, key=None):
    '''Fetch a measuerment with it=measurement_id'''
    '''api changed probably this one :
    https://atlas.ripe.net/api/internal/measurement-latst/%s/
    however this one has less junk
    https://atlas.ripe.net/api/internal/measurement-latest/%s/
    '''
    url = "https://atlas.ripe.net/api/internal/measurement-latest/%s/" % measurement_id
    if (key):
        url = url + "?key=%s" % key
    return get_response(url)


def parse_measurements(measurements, measurement_type, message):
    '''Parse the measuerment'''
    parsed_measurements = []
    for probe_id, measurement in measurements.iteritems():
        if measurement == None:
            message.add_error(probe_id, "No data")
            continue
        parsed_measurements.append(
            {
                'a': MeasurmentDnsA,
                'aaaa': MeasurmentDnsAAAA,
                'cname': MeasurmentDnsCNAME,
                'ds': MeasurmentDnsDS,
                'dnskey' : MeasurmentDnsDNSKEY,
                'soa': MeasurmentDnsSOA,
                'http': MeasurmentHTTP,
                'ping': MeasurmentPing,
                'ssl': MeasurmentSSL,
            }.get(measurement_type.lower(), Measurment)(probe_id, measurement)
        )
        #parsed_measurements.append(MeasurmentSSL(probe_id, measurement[5]))
    return parsed_measurements


def check_measurements(measurements, args, message):
    '''check the measuerment'''
    for measurement in measurements:
        measurement.check(args, message)
