#!/usr/bin/env python
import atlas
import urllib2
import json
import sys

class JsonRequest(urllib2.Request):
    '''Object to make a Json HTTP request'''
    def __init__(self, url):
        urllib2.Request.__init__(self, url)
        self.add_header("Content-Type", "application/json")
        self.add_header("Accept", "application/json")

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
        print '''Unknown: Fatal error when reading request 
                (%s): %s''' % (error.code, error.read())
        sys.exit(3)

def get_measurements( measurement_id):
    '''Fetch a measuerment with it=measurement_id'''
    url = "https://atlas.ripe.net/api/v1/measurement/%s/latest/" \
            % measurement_id
    return get_response(url)

def parse_measurements(measurements, measurement_type, nagios_message):
    '''Parse the measuerment'''
    parsed_measurements = []
    for measurement in measurements:
        probe_id = measurement[1]
        if measurement[5] == None:
            nagios_message.add_error(
                    "Probe (%s) has no nagios_message" % (probe_id))
            continue
        parsed_measurements.append(
            {
                'dns': atlas.DnsMeasurment,
                'dns6': atlas.DnsMeasurment,
                'http': atlas.HttpMeasurment,
                'http6': atlas.HttpMeasurment,
                'ping6': atlas.PingMeasurment,
                'ping': atlas.PingMeasurment,
                'sslcert6': atlas.SSLcertMeasurment,
                'sslcert': atlas.SSLcertMeasurment,
            }.get(measurement_type, atlas.Measurment)(probe_id, measurement[5])
        )
        #parsed_measurements.append(SSLcertMeasurment(probe_id, measurement[5]))
    return parsed_measurements 

def check_measurements(measurements, nagios_args, nagios_message):
    '''check the measuerment'''
    for measurement in measurements:
        measurement.check(nagios_args, nagios_message)

def main():
    '''main rutine'''
    nagios_message = atlas.NagiosMessage(2)
    ssl_measurement_id = 1010510
    ssl6_measurement_id = 1004237
    ping_measurement_id = 1000002
    ping6_measurement_id = 1003985
    http_measurement_id = 1003951
    http6_measurement_id = 1003930
    dns_measurement_id = 1012167
#    dns_measurement_id = 1012172
    dns6_measurement_id = 1004048
    measurement_id = dns_measurement_id
    nagios_args = {}
    nagios_args['sha1hash'] = "C62995469F6F81B576012F3C7EF674E03DBC630483E2D278455EAF2F2C70A06E"
    nagios_args['common_name'] = "*.facebook.com"
    nagios_args['max_measurement_age'] = 30
    nagios_args['check_expiry'] = True
    nagios_args['status_code'] = '200'

    nagios_args['soa'] = { 'mname': None, 'rname': None, 'serial': None, 'refresh': None, 'update': None, 'expire': None, 'nxdomain': None }
    nagios_args['soa']['mname'] = "ns.johnbond.org"
    nagios_args['soa']['rname'] = "dns.johnbond.org"
    nagios_args['soa']['serial'] = "2013022201"
    nagios_args['soa']['refresh'] = "3600"
    nagios_args['soa']['update'] = "600"
    nagios_args['soa']['expire'] = "864000"
    nagios_args['soa']['nxdomain'] = "3600"

    nagios_args['flags'] = "QR,RD,RA,BO"

    nagios_args['rtt'] = { 'min':0, 'max':0, 'avg':0 }
    nagios_args['rtt']['min'] = 60
    nagios_args['rtt']['max'] = 60
    nagios_args['rtt']['avg'] = 60
    nagios_args['warn_expiry'] = 30
    nagios_args['rcode'] = 'NOERROR'
    measurement_type = 'sslcert'
    measurement_type = 'ping'
    measurement_type = 'http'
    measurement_type = 'dns'
    measurements =  get_measurements(measurement_id)
    parsed_measurements = parse_measurements(measurements, measurement_type, nagios_message)
    check_measurements(parsed_measurements, nagios_args, nagios_message)
    nagios_message.exit()
main()
