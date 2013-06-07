#!/usr/bin/env python
import urllib2
import urllib
import json
import time
import os
import sys
import time

class JsonRequest(urllib2.Request):
    def __init__(self, url):
        urllib2.Request.__init__(self, url)
        self.add_header("Content-Type", "application/json")
        self.add_header("Accept", "application/json")

def create_measurment(api_key, target, requested, area, ip_version, verbose):
    url = "https://atlas.ripe.net/api/v1/measurement/?key=%s" % api_key
    data = { "definitions": [ { 
                "target": target, 
                "description": "SSL %s" % target,
                "type": "sslcert", 
                "af": ip_version,
                "resolve_on_probe": True
                } ],
            "probes": [ { 
                "requested": requested, 
                "type": "area",
                "value": area
                } ] }
    json_data = json.dumps(data)
    request = JsonRequest(url)
    try:
        conn = urllib2.urlopen(request, json_data)
        results = json.load(conn)
        measurement = results["measurements"][0]
        print ("%s : %s " % ( target, measurement))
        conn.close()
        return measurement
    except urllib2.HTTPError as e:
        if e.code ==  404:
            if verbose:
                print "%s 404 retrying" % \
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) 
        else:
            print >>sys.stderr, ("Fatal error when submitting request (%s): %s\n%s" % ( e.code, e.read(), json_data))
            sys.exit(1)
def get_probe_count(measurement, requested, verbose):
    url = "https://atlas.ripe.net/api/v1/measurement/%s/?fields="
    # READ: https://github.com/RIPE-Atlas-Community/ripe-atlas-community-contrib/blob/master/reachability%2Bretrieve.py
    fields_delay_base = 3
    fields_delay_factor = 0.2
    enough = False
    fields_delay = fields_delay_base + (requested * fields_delay_factor)
    num_probes = 0
    while not enough:
        time.sleep(fields_delay)
        fields_delay *= 2
        request = JsonRequest(url % measurement)
        status = ""
        try:
            conn = urllib2.urlopen(request)
            meta = json.load(conn)
            status = meta["status"]["name"]
            if status == "Specified" or status == "Scheduled":
            # Not done, loop
                if verbose:
                    print "%s list of allocated probes not ready" % \
                        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) 
            elif status == "Ongoing":
                enough = True
                num_probes = len(meta["probes"])
                print "%s probes allocated" % num_probes
            else:
                print >>sys.stderr, meta
                print >>sys.stderr, ("Internal error, unexpected status when querying the measurement fields: \"%s\"" % meta["status"])
                #sys.exit(1) 
            conn.close()
            return num_probes
        except urllib2.HTTPError as e:
            print >>sys.stderr, ("Fatal error when querying fields (%s): %s\nStatus: %s" % (e.code, e.read(),status))
            sys.exit(1)
def get_results( measurement, num_probes, verbose):
    url_results = "https://atlas.ripe.net/api/v1/measurement/%s/result/" 
    percentage_required = 0.9 # Percentage of responding probes before we stop
    enough = False
    status = ""
    elapsed = 0
    meta = None
    while not enough: 
        time.sleep(5) 
        request = JsonRequest(url_results % measurement)
        try:
            conn = urllib2.urlopen(request)
            meta = json.load(conn) 
            num_results = len(meta)
            if num_results >= num_probes*percentage_required:
                enough = True
            else:
                status = meta["status"]["name"]
                if status == "Ongoing":
                    # Wait a bit more
                    if verbose:
                        print "%s measurement not over, only %s/%s probes reported" % \
                            (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            num_results, num_probes)
                elif status == "Stopped":
                    print "stopping"
                    enough = True # Even if not enough probes
                else:
                    print >>sys.stderr, \
                      ("Internal error, unexpected status when retrieving the measurement: \"%s\"" % \
                       meta["status"])
                    sys.exit(1)
            conn.close()
            return meta
        except urllib2.HTTPError as e:
            if e.code ==  404:
                if verbose:
                    print "Results %s: 404 retrying" % \
                        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) 
            else:
                print >>sys.stderr, ("Fatal error when reading results (%s): %s\nStatus: %s" % (e.code, e.read(), status))
                sys.exit(1)

def main():
    fetch_key = ""
    create_key = ""
    target = "www.facebook.com"
    requested = 5
    area = "WW"
    measurement = create_measurment(create_key, target, requested, area,  4, True)
    num_probes = get_probe_count(measurement, requested, True)
    results = get_results(measurement, num_probes, True)
    print results
main()
