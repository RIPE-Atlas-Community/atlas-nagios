#!/usr/bin/env python
import atlas
import urllib2
import json

class JsonRequest(urllib2.Request):
    def __init__(self, url):
        urllib2.Request.__init__(self, url)
        self.add_header("Content-Type", "application/json")
        self.add_header("Accept", "application/json")

def get_response (url):
    print url
    request = JsonRequest(url)
    try:
        conn = urllib2.urlopen(request)
        json_data = json.load(conn)
        conn.close()
        return json_data
    except urllib2.HTTPError as e:
       print "Unknown: Fatal error when reading results (%s): %s, Status: %s" % (e.code, e.read(), status)
       sys.exit(3)

def get_measurements( measurement_id):
    url = "https://atlas.ripe.net/api/v1/measurement/%s/latest/" % measurement_id
    return get_response(url)

def parse_measurements(measurements, measurement_type, results):
    parsed_measurements = []
    for measurement in measurements:
        probe_id = measurement[1]
        if measurement[5] == None:
            results['error'].append("Probe (%s) has no results" % (probe_id))
            continue
        parsed_measurements.append(
            {
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

def check_measurements(measurements, nagios_args, results):
    for measurement in measurements:
        measurement.check(nagios_args, results)

def main():
    results = { 'ok': [], 'warn': [], 'error': [] }
    ssl_measurement_id = 1010510
    ssl6_measurement_id = 1004237
    ping_measurement_id = 1000002
    ping6_measurement_id = 1003985
    http_measurement_id = 1003951
    http6_measurement_id = 1003930
    dns_measurement_id = 1004045
    dns6_measurement_id = 1004048
    measurement_id = http6_measurement_id
    nagios_args = {}
    nagios_args['sha1hash'] = "C62995469F6F81B576012F3C7EF674E03DBC630483E2D278455EAF2F2C70A06E"
    nagios_args['common_name'] = "*.facebook.com"
    nagios_args['max_measurement_age'] = 30
    nagios_args['check_expiry'] = True
    nagios_args['status_code'] = '200'

    nagios_args['rtt'] = { 'min':0, 'max':0, 'avg':0 }
    nagios_args['rtt']['min'] = 60
    nagios_args['rtt']['max'] = 60
    nagios_args['rtt']['avg'] = 60
    nagios_args['warn_expiry'] = 30
    measurement_type = 'sslcert'
    measurement_type = 'ping'
    measurement_type = 'http'
    measurements =  get_measurements(measurement_id)
    parsed_measurements = parse_measurements(measurements, measurement_type, results)
    check_measurements(parsed_measurements, nagios_args, results)
    print results
main()
