#!/usr/bin/env python
import urllib2
import urllib
import json
import time
import os
import sys

class JsonRequest(urllib2.Request):
    def __init__(self, url):
        urllib2.Request.__init__(self, url)
        self.add_header("Content-Type", "application/json")
        self.add_header("Accept", "application/json")

def check_string(probe_id, check_string, probe_string, check_type, results):
    if check_string == probe_string:
        results['ok'].append("Probe (%s) detected correct %s: %s " % (probe_id, check_type, probe_string))
    else:
        results['error'].append("Probe (%s) detected incorrect %s: %s " % (probe_id, check_type, probe_string))

def check_max_age(probe_id, max_age, check_time, results):
    min_time = time.time() - max_age
    if check_time < min_time:
        results['error'].append("Probe (%s) results too old: %s " % (probe_id, time.ctime(check_time)))
    else:
        results['ok'].append("Probe (%s) results fresh: %s " % (probe_id, time.ctime(check_time)))

def check_expiry(probe_id, expiry, warn_expiry, results):
    current_time = time.time()
    warn_time = current_time - (warn_expiry * 60 * 60 * 24) 
    expiry = time.mktime(time.strptime(expiry,"%Y%m%d%H%M%SZ"))
    if expiry < current_time:
        results['error'].append("Probe (%s) certificate expiered: %s " % (probe_id, time.ctime(expiry)))
    elif expiry < warn_time:
        results['warn'].append("Probe (%s) certificate expires soon: %s " % (probe_id, time.ctime(expiry)))
    else:
        results['ok'].append("Probe (%s) certificate expiry good: %s " % (probe_id, time.ctime(expiry)))
        
def check_rtt(probe_id, min_rtt, rtt, results):
    if rtt < min_rtt:
        results['ok'].append("Probe (%s) rtt is good: %s " % (probe_id, rtt))
    else:
        results['error'].append("Probe (%s) rtt above limit (%s): %s " % (probe_id, min_rtt, rtt))

def parse_ping ( meassuerment, check_args, results):
    probe_id = meassuerment[1]
    rtt = meassuerment[5][0]
    if 'min_rtt' in check_args:
        check_rtt(probe_id, check_args['min_rtt'], rtt, results)


def parse_sslcert ( meassuerment, check_args, results):
    avg_rtt = meassuerment[0]
    probe_id = meassuerment[1]

    check_time = meassuerment[5][1]
    common_name = meassuerment[5][2][0][0]
    expiry = meassuerment[5][2][0][4]
    sha1 = meassuerment[5][2][0][5]
    if 'max_measurement_age' in check_args:
        check_max_age(probe_id, check_args['max_measurement_age'], check_time, results)
    if 'sha1hash' in check_args:
        check_string(probe_id, check_args['sha1hash'], sha1, 'sha1hash', results)
    if 'common_name' in check_args:
        check_string(probe_id, check_args['common_name'], common_name, 'cn', results)
    if check_args['check_expiry'] and 'warn_expiry' in check_args:
        check_expiry(probe_id, expiry, check_args['warn_expiry'], results)
    return { 'cn': common_name, 'expiry': expiry, 'sha1': sha1 }

def unknown_type(measurement, check_args, results):
    #we should never get here because i should be checking for this earlier
    print "Unknown: Unable to parse measruement type:"  
    sys.exit(3)

def parse_measurements(measurements, measurement_type, check_args, results):
    parsed_measurements = []
    for measurement in measurements:
        if measurement[5] == None:
            results['error'].append("Probe (%s) has no results" % (probe_id))
            next
        parsed_measurements.append(
            { 
                'ping6': parse_ping,
                'ping': parse_ping,
                'sslcert6': parse_sslcert,
                'sslcert': parse_sslcert,
            }.get(measurement_type, unknown_type)(measurement, check_args, results)
        )
    return parsed_measurements

def get_measurements( measurement_id):
    url = "https://atlas.ripe.net/api/v1/measurement/%s/latest/" % measurement_id
    request = JsonRequest(url)

    try:
        print url
        conn = urllib2.urlopen(request)
        measurements = json.load(conn)
        conn.close()
        return measurements
    except urllib2.HTTPError as e:
       print "Unknown: Fatal error when reading results (%s): %s, Status: %s" % (e.code, e.read(), status)
       sys.exit(3)

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
    measurement_id = http_measurement_id
    measurement_type = 'sslcert'
    measurement_type = 'http'
    
    check_args = {}
    check_args['sha1hash'] = "C62995469F6F81B576012F3C7EF674E03DBC630483E2D278455EAF2F2C70A06E"
    check_args['common_name'] = "*.facebook.com"
    check_args['max_measurement_age'] = 1
    check_args['check_expiry'] = True
    check_args['min_rtt'] = 60
    #in days
    check_args['warn_expiry'] = 30

    measurements =  get_measurements(measurement_id)
    parsed_measurements = parse_measurements(measurements, measurement_type, check_args, results) 
    print results

main()
