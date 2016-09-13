#Copyright (c) 2014, John Bond <mail@johnbond.org>
#All rights reserved.
#
#Redistribution and use in source and binary forms, with or without
#modification, are permitted provided that the following conditions are met: 
#
#1. Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer. 
#2. Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution. 
#
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
#ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import sys
import time
import argparse
import requests
import json
import pprint
from ripe.atlas.cousteau import AtlasLatestRequest

from measurements import *

def ensure_list(list_please):
    """make @list_please a list if it isn't one already"""
    if type(list_please) != list:
        return [(list_please)]
    else:
        return list_please

def get_response(url):
    '''Fetch a Json Object from url'''
    try:
        request = requests.get(url)
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
    '''Fetch a measuerment with id=measurement_id'''

    kwargs = {"msm_id": measurement_id}
    if key:
        kwargs["key"] = key

    is_success, response = AtlasLatestRequest(**kwargs).create()

    if not is_success:
        print "Unexpected error: %s".format(response)
        sys.exit(3)

    return response


def parse_measurements(measurements, measurement_type):
    '''Parse the measuerment'''
    parsed_measurements = []
    for measurement in measurements:
        parsed_measurements.append(
            {
                'a': MeasurmentDnsA,
                'aaaa': MeasurmentDnsAAAA,
                'ds': MeasurmentDnsDS,
                'dnskey' : MeasurmentDnsDNSKEY,
                'mx' : MeasurmentDnsMX,
                'ns' : MeasurmentDnsNS,
                'soa': MeasurmentDnsSOA,
                'http': MeasurmentHTTP,
                'ping': MeasurmentPing,
                'ssl': MeasurmentSSL,
            }.get(measurement_type.lower(), Measurment)(measurement["prb_id"], measurement)
        )
    return parsed_measurements


def check_measurements(measurements, args, message):
    '''check the measuerment'''
    for measurement in measurements:
        measurement.check(args, message)


