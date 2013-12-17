import sys
import time
import argparse
import requests
import json
import pprint
import urllib2

from measurements import *

def ensure_list(list_please):
    """make @list_please a list if it isn't one already"""
    if type(list_please) != list:
        return [(list_please)]
    else:
        return list_please

def get_response (url):
    '''Fetch a Json Object from url'''
    #print url
    request = JsonRequest(url)
    try:
        conn = urllib2.urlopen(request)
        json_data = json.load(conn)
        conn.close()
        return json_data
    except urllib2.HTTPError as error:
        print "Unknown: Fatal error when reading request, (%s): %s" % (error.code, error.read())
        sys.exit(3)


def get_measurements(measurement_id, key=None):
    '''Fetch a measuerment with it=measurement_id'''
    '''api changed probably this one :
    https://atlas.ripe.net/api/internal/measurement-latst/%s/
    however this one has less junk
    https://atlas.ripe.net/api/internal/measurement-latest/%s/
    '''
    url = "https://atlas.ripe.net/api/v1/measurement/%s/latest/" % measurement_id
    if (key):
        url = url + "?key=%s" % key
    return get_response(url)


def parse_measurements(measurements, measurement_type, message):
    '''Parse the measuerment'''
    parsed_measurements = []
    for measurement in measurements:
        probe_id = measurement[1]
        if measurement[5] == None:
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
            }.get(measurement_type.lower(), Measurment)(probe_id, measurement[5])
        )
        #parsed_measurements.append(MeasurmentSSL(probe_id, measurement[5]))
    return parsed_measurements


def check_measurements(measurements, args, message):
    '''check the measuerment'''
    for measurement in measurements:
        measurement.check(args, message)
