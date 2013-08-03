#!/usr/bin/env python
""" Class to use the ripe atlas platform to do nagios checks """
import time, sys, argparse, urllib2, json

class NagiosMessage:
    """Object to store nagios messages"""
    def __init__(self, verbose):
        """
        Initialise Object
        verbose is an interger indicating how Much information to return
        """
        self.error = []
        self.warn = []
        self.ok = []
        self.verbose = verbose

    def add_error(self, message):
        """Add an error message"""
        self.error.append(message)

    def add_warn(self, message):
        """Add an warn message"""
        self.warn.append(message)

    def add_ok(self, message):
        """Add an ok message"""
        self.ok.append(message)

    def exit(self):
        """Parse the nagios_message and exit correctly for nagios"""
        if len(self.error) > 0:
            if self.verbose > 0:
                print "ERROR: %d: %s" % (len(self.error),
                        ", ".join(self.error))
                if self.verbose > 1:
                    print "WARN: %d: %s" % (len(self.warn),
                            ", ".join(self.warn))
                    print "OK: %d: %s" % (len(self.ok),
                        ", ".join(self.ok))

            else:
                print "ERROR: %d" % len(self.error)
            sys.exit(2)
        elif len(self.warn) > 0:
            if self.verbose > 0:
                print "WARN: %d: %s" % (len(self.warn),
                        ", ".join(self.warn))
                if self.verbose > 1:
                    print "OK: %d: %s" % (len(self.ok),
                        ", ".join(self.ok))
            else:
                print "WARN: %d" % len(self.warn)
            sys.exit(1)
        else:
            if self.verbose > 1:
                print "OK: %d: %s" % (len(self.ok),
                    ", ".join(self.ok))
            else:
                print "OK: %d" % len(self.ok)
            sys.exit(0)

class Measurment: 
    """Parent object for an atlas measurment"""

    def __init__(self, probe_id, payload):    
        """Initiate generic message data""" 
        self.probe_id = probe_id
        self.payload = payload
        self.check_time = self.payload[1]
        self.msg = "Probe (%s): %s (%s)" 

    def check_measurement_age(self, max_age, nagios_message):
        """Check if a measerment is fresh enough"""
        min_time = time.time() - max_age
        check_time_str = time.ctime(self.check_time)
        if self.check_time < min_time:
            nagios_message.add_error(self.msg % \
                    (self.probe_id, "measurement to old", check_time_str))
        else:
            nagios_message.add_ok(self.msg % \
                    (self.probe_id, "measurement fresh", check_time_str))

    def check_string(self, check_string, measurment_string, 
            check_type, nagios_message):
        """Generic check to compare two strings"""
        if check_string == measurment_string:
            nagios_message.add_ok(self.msg % \
                    (self.probe_id, check_type, measurment_string))
        else:
            nagios_message.add_error(self.msg % \
                     (self.probe_id, check_type, measurment_string))

    def check(self, args, nagios_message):             
        """main check fucntion"""
        if args.max_measurement_age != False:
            self.check_measurement_age(
                    args.max_measurement_age, nagios_message)

class SSLcertMeasurment(Measurment):
    """Object for an atlas SSL Measurment"""

    def __init__(self, probe_id, payload):
        """Initiate object"""
        #super(Measurment, self).__init__(payload)
        Measurment.__init__(self, probe_id, payload)
        self.common_name = self.payload[2][0][0]
        self.expiry = time.mktime(
                time.strptime(self.payload[2][0][4],"%Y%m%d%H%M%SZ"))
        self.sha1 = self.payload[2][0][5]

    def check_expiry(self, warn_expiry, nagios_message):
        """Check if the certificat is going to expire before warn_expiry"""
        current_time = time.time()
        warn_time = current_time - (warn_expiry * 60 * 60 * 24)
        expiry_str = time.ctime(self.expiry)
        if self.expiry < current_time:
            nagios_message.add_error(self.msg % (
                    self.probe_id, "certificate expierd", expiry_str))
        elif self.expiry < warn_time:
            nagios_message.add_warn(self.msg % (
                    self.probe_id, "certificate expires soon", expiry_str))
        else:
            nagios_message.add_ok(self.msg % (
                    self.probe_id, "certificate expiry good", expiry_str))

    def check(self, args, nagios_message):
        """Main SSL check routine"""
        Measurment.check(self, args, nagios_message)
        if args.sha1hash:
            self.check_string( args.sha1hash, 
                    self.sha1, 'sha1hash', nagios_message)
        if args.common_name:
            self.check_string( args.common_name, 
                    self.common_name, 'cn', nagios_message)
        if args.sslexpiry:
            self.check_expiry(args.sslexpiry, nagios_message)

class PingMeasurment(Measurment):
    """Object for an atlas Ping Measurment"""

    def __init__(self, probe_id, payload):
        """Initiate object"""
        #super(Measurment, self).__init__(self, payload)
        Measurment.__init__(self, probe_id, payload)
        self.avg_rtt = self.payload[0]

    def check_rtt(self, check_type, rtt, nagios_message):
        """Check the return trip time islower then rtt"""
        msg = "desierd (%s), real (%s)" % (rtt, self.avg_rtt)
        if self.avg_rtt < rtt:
            nagios_message.add_ok(self.msg % (
                    self.probe_id, msg, "Ping %s" % check_type))
        else:
            nagios_message.add_error(self.msg % (
                    self.probe_id, msg, "Ping %s" % check_type))

    def check(self, args, nagios_message):
        """Main ping check routine"""
        Measurment.check(self, args, nagios_message)

        if args.rtt_min:
            self.check_rtt("min", args.rtt_min, nagios_message) 
        if args.rtt_max:
            self.check_rtt("max", args.rtt_max, nagios_message) 
        if args.rtt_avg:
            self.check_rtt("avg", args.rtt_avg, nagios_message) 



class HttpMeasurment(Measurment):
    """Object for an atlas HTTP Measurment"""

    def __init__(self, probe_id, payload):
        """Initiate object"""
        #super(Measurment, self).__init__(self, payload)
        Measurment.__init__(self, probe_id, payload)
        try:
            self.status = self.payload[2][0]['res']
        except KeyError:
            try:
                self.status = self.payload[2][0]['dnserr']
            except KeyError:
                #probably a time out, should use a better status code
                self.status = 500

    def check_status(self, check_status, nagios_message):
        """check the HTTP status is the same as check_status"""
        msg = "%s: desierd (%s), real (%s)" % \
                (self.probe_id, check_status, self.status)
        try:
            if int(self.status) == int(check_status):
                nagios_message.add_ok(self.msg % (
                        self.probe_id, msg, "HTTP Status Code"))
            else:
                nagios_message.add_error(self.msg % (
                        self.probe_id, msg, "HTTP Status Code"))
        except ValueError:
            nagios_message.add_error(self.msg % (
                    self.probe_id, msg, "HTTP Status Code"))

    def check(self, args, nagios_message):
        """Main HTTP check routine"""
        Measurment.check(self, args, nagios_message)
        if args.status_code:
            self.check_status(args.status_code, nagios_message)

class DnsAnswer:
    """Parent class to hold dns measuerment payloads"""

    def __init__(self, probe_id, answer):
        """Initiate object"""
        self.answer = answer
        self.probe_id = probe_id
        self.msg = "Probe (%s): %s (%s)" 

    def check_string(self, check_type, 
            measurment_string, check_string, nagios_message):
        """Generic function to compare two strings"""
        if check_string == measurment_string:
            nagios_message.add_ok(self.msg % (
                    self.probe_id, check_type, measurment_string))
        else:
            nagios_message.add_error(
                    self.msg % (self.probe_id, check_type, measurment_string))

    def check(self, args, nagios_message):
        """Main Check routine"""
        raise NotImplementedError("Subclasses should implement this!")

class SoaAnswer(DnsAnswer):
    """Parent class to hold dns SOA measuerment payloads"""
    def __init__(self, probe_id, answer ):
        DnsAnswer.__init__(self, probe_id, answer)
        if "SOA" in self.answer:
            self.qname, self.ttl, _,  self.rrtype, self.mname, \
                    self.rname, self.serial, self.refresh, self.update, \
                    self.expire, self.nxdomain = answer.split()
        else:
            #i think the only other posibility is CNAME?
            #print self.answer
            _, _, _, self.rrtype, _ = self.answer.split(None, 5)

    def check(self, args, nagios_message):
        """Main Check routine"""
        if self.rrtype != "SOA": 
            nagios_message.add_error(self.msg % (
                    self.probe_id, "Answer is not SOA", self.rrtype))
            return
        if args.mname:
            self.check_string("mname", self.mname, args.mname, nagios_message) 


class DnsMeasurment(Measurment):
    """Parent class for a dns measuerment"""

    def __init__(self, probe_id, payload):
        """Initiate Object"""
        #super(Measurment, self).__init__(self, payload)
        Measurment.__init__(self, probe_id, payload)
        self.additional = self.payload[2]['additional']
        self.question = { 'qname': "", 'qtype': "", 'question':"" }
        self.question['qname'], _, self.question['qtype'] = \
                self.payload[2]['question'].split()
        self.authority = self.payload[2]['authority']
        self.rcode = self.payload[2]['rcode']
        self.flags = self.payload[2]['flags']
        self.answer = None
        if self.rcode == "NOERROR":
            self.answer = {
                    "SOA": SoaAnswer,
            }.get(self.question['qtype'], DnsAnswer)(
                    self.probe_id, self.payload[2]['answer'])

    def check_rcode(self, rcode, nagios_message):
        """Check the RCODE is the same as rcode"""
        msg = "desierd (%s), real (%s)" % ( rcode, self.rcode)
        if self.rcode == rcode:
            nagios_message.add_ok(self.msg % (
                    self.probe_id, msg, "DNS RCODE"))
        else:
            nagios_message.add_error(self.msg % (
                    self.probe_id, msg, "DNS RCODE"))

    def check_flags(self, flags, nagios_message):
        """Check the flags returned in the check are the same as flags"""
        for flag in flags.split(","):
            if flag in self.flags.split(): 
                nagios_message.add_ok(self.msg % (
                        self.probe_id, "Flag found", flag))
            else:
                nagios_message.add_error(self.msg % (
                        self.probe_id, "Flag Missing ", flag))

    def check(self, args, nagios_message):
        """Main Check routine"""
        Measurment.check(self, args, nagios_message)
        if 'rcode' in args:
            self.check_rcode(args['rcode'], nagios_message)
        if 'flags' in args:
            self.check_flags(args['flags'], nagios_message)

        if self.rcode == "NOERROR":
            self.answer.check(args, nagios_message)

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
                    "Probe (%s) has no data" % (probe_id))
            continue
        parsed_measurements.append(
            {
                'dns': DnsMeasurment,
                'http': HttpMeasurment,
                'ping': PingMeasurment,
                'ssl': SSLcertMeasurment,
            }.get(measurement_type, Measurment)(probe_id, measurement[5])
        )
        #parsed_measurements.append(SSLcertMeasurment(probe_id, measurement[5]))
    return parsed_measurements

def check_measurements(measurements, args, nagios_message):
    '''check the measuerment'''
    for measurement in measurements:
        measurement.check(args, nagios_message)

def arg_parse():
    """Parse arguments"""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers( 
            title="Supported Measuerment types", dest='name')

    #measuerement types
    parser_ssl = subparsers.add_parser('ssl', help='SSL check')
    parser_http = subparsers.add_parser('http', help='HTTP check')
    parser_ping = subparsers.add_parser('ping', help='Ping check')
    parser_dns = subparsers.add_parser('dns', help='DNS check')

    #ssl args
    parser_ssl.add_argument('-v', '--verbose', action='count',
            help='increase verbosity')
    parser_ssl.add_argument("measurement_id",
            help="Measuerment ID to check")
    parser_ssl.add_argument('--max_measurement_age', type=int, default=30,
            help='The max age of a measuerment in unix time')
    parser_ssl.add_argument('--common_name',
            help='Ensure a cert has this cn')
    parser_ssl.add_argument('--sslexpiry', type=int, default=30,
            help="Ensure certificate dosne't expire in x days")
    parser_ssl.add_argument('--sha1hash',
            help="Ensure certificate has this sha1 hash")
    #Ping args
    parser_ping.add_argument('-v', '--verbose', action='count',
            help='increase verbosity')
    parser_ping.add_argument("measurement_id",
            help="Measuerment ID to check")
    parser_ping.add_argument('--max_measurement_age', type=int, default=30,
            help='The max age of a measuerment in unix time')
    parser_ping.add_argument('--rtt_max',
            help='Ensure the max ttl is below this')
    parser_ping.add_argument('--rtt_min',
            help='Ensure the min ttl is below this')
    parser_ping.add_argument('--rtt_avg',
            help='Ensure the avg ttl is below this')
    #HTTP args
    parser_http.add_argument('-v', '--verbose', action='count',
            help='increase verbosity')
    parser_http.add_argument("measurement_id", help="Measuerment ID to check")
    parser_http.add_argument('--max_measurement_age', type=int, default=30,
            help='The max age of a measuerment in unix time')
    parser_http.add_argument('--status_code', type=int, default=200,
            help='Ensure the site returns this status code')
    #DNS args
    subparsers_dns = parser_dns.add_subparsers(
            title='Supported DNS checks', dest='name')
    parser_dns_soa = subparsers_dns.add_parser('soa', help='soa check')

    #DNS SOA OPTIONS
    parser_dns_soa.add_argument('-v', '--verbose', action='count',
            help='increase verbosity')
    parser_dns_soa.add_argument("measurement_id", help="Measuerment ID to check")
    parser_dns_soa.add_argument('--max_measurement_age', type=int, default=30,
            help='The max age of a measuerment in unix time')
    parser_dns_soa.add_argument('--mname',
            help='Ensure the soa has this mname')
    parser_dns_soa.add_argument('--rname',
            help='Ensure the soa has this rname')
    parser_dns_soa.add_argument('--serial',
            help='Ensure the soa has this serial')
    parser_dns_soa.add_argument('--refresh',
            help='Ensure the soa has this refresh')
    parser_dns_soa.add_argument('--update',
            help='Ensure the soa has this update')
    parser_dns_soa.add_argument('--expire',
            help='Ensure the soa has this expire')
    parser_dns_soa.add_argument('--nxdomain',
            help='Ensure the soa has this nxdomain')
    return parser.parse_args()

def main():
    """main function"""
    args = arg_parse()
    nagios_message = NagiosMessage(args.verbose)
    measurements =  get_measurements(args.measurement_id)
    parsed_measurements = parse_measurements(
            measurements, args.name, nagios_message)
    check_measurements(parsed_measurements, args, nagios_message)
    nagios_message.exit()
if __name__ == '__main__':
    main()
