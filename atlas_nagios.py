#!/usr/bin/env python
""" Class to use the ripe atlas platform to do nagios checks """
import sys
import time
import argparse
import urllib2
import json


def ensure_list(list_please):
    """make @list_please a slit if it isn't one already"""
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
        print '''Unknown: Fatal error when reading request
                (%s): %s''' % (error.code, error.read())
        sys.exit(3)


def get_measurements( measurement_id):
    '''Fetch a measuerment with it=measurement_id'''
    url = "https://atlas.ripe.net/api/v1/measurement/%s/latest/" \
            % measurement_id
    return get_response(url)


def parse_measurements(measurements, measurement_type, message):
    '''Parse the measuerment'''
    parsed_measurements = []
    for measurement in measurements:
        probe_id = measurement[1]
        if measurement[5] == None:
            message.add_error(
                    "Probe (%s) has no data" % (probe_id))
            continue
        parsed_measurements.append(
            {
                'a': MeasurmentDnsA,
                'aaaa': MeasurmentDnsAAAA,
                'cname': MeasurmentDnsCNAME,
                'ds': MeasurmentDnsDS,
                'dnskey' : MeasurementDnsDNSKEY,
                'soa': MeasurmentDnsSOA,
                'http': MeasurmentHTTP,
                'ping': MeasurmentPing,
                'ssl': MeasurmentSSL,
            }.get(measurement_type, Measurment)(probe_id, measurement[5])
        )
        #parsed_measurements.append(MeasurmentSSL(probe_id, measurement[5]))
    return parsed_measurements


def check_measurements(measurements, args, message):
    '''check the measuerment'''
    for measurement in measurements:
        measurement.check(args, message)



class Message:
    """Object to store nagios messages"""
    def __init__(self, verbose):
        """
        Initialise Object
        verbose is an interger indicating how Much information to return
        """
        #need to group these by probe id
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
        """Parse the message and exit correctly for nagios"""
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

    @staticmethod
    def add_args(parser):
        """add SSL arguments"""
        parser.add_argument('-v', '--verbose', action='count',
                help='increase verbosity')
        parser.add_argument("measurement_id",
                help="Measuerment ID to check")
        parser.add_argument('--max_measurement_age', type=int, default=30,
                help='The max age of a measuerment in unix time')

    def check_measurement_age(self, max_age, message):
        """Check if a measerment is fresh enough"""
        min_time = time.time() - max_age
        check_time_str = time.ctime(self.check_time)
        if self.check_time < min_time:
            message.add_error(self.msg % \
                    (self.probe_id, "measurement to old", check_time_str))
        else:
            message.add_ok(self.msg % \
                    (self.probe_id, "measurement fresh", check_time_str))

    def check_string(self, check_string, measurment_string, 
            check_type, message):
        """Generic check to compare two strings"""
        if check_string == measurment_string:
            message.add_ok(self.msg % \
                    (self.probe_id, check_type, measurment_string))
        else:
            message.add_error(self.msg % \
                     (self.probe_id, check_type, measurment_string))

    def check(self, args, message):             
        """main check fucntion"""
        if args.max_measurement_age != False:
            self.check_measurement_age(
                    args.max_measurement_age, message)


class MeasurmentSSL(Measurment):
    """Object for an atlas SSL Measurment"""

    def __init__(self, probe_id, payload):
        """Initiate object"""
        #super(Measurment, self).__init__(payload)
        Measurment.__init__(self, probe_id, payload)
        self.common_name = self.payload[2][0][0]
        self.expiry = time.mktime(
                time.strptime(self.payload[2][0][4],"%Y%m%d%H%M%SZ"))
        self.sha1 = self.payload[2][0][5]

    @staticmethod
    def add_args(subparser):
        """add SSL arguments"""
        parser = subparser.add_parser('ssl', help='SSL check')
        Measurment.add_args(parser)
        parser.add_argument('--common_name',
                help='Ensure a cert has this cn')
        parser.add_argument('--sslexpiry', type=int, default=30,
                help="Ensure certificate dosne't expire in x days")
        parser.add_argument('--sha1hash',
                help="Ensure certificate has this sha1 hash")

    def check_expiry(self, warn_expiry, message):
        """Check if the certificat is going to expire before warn_expiry"""
        current_time = time.time()
        warn_time = current_time - (warn_expiry * 60 * 60 * 24)
        expiry_str = time.ctime(self.expiry)
        if self.expiry < current_time:
            message.add_error(self.msg % (
                    self.probe_id, "certificate expierd", expiry_str))
        elif self.expiry < warn_time:
            message.add_warn(self.msg % (
                    self.probe_id, "certificate expires soon", expiry_str))
        else:
            message.add_ok(self.msg % (
                    self.probe_id, "certificate expiry good", expiry_str))

    def check(self, args, message):
        """Main SSL check routine"""
        Measurment.check(self, args, message)
        if args.sha1hash:
            self.check_string( args.sha1hash, 
                    self.sha1, 'sha1hash', message)
        if args.common_name:
            self.check_string( args.common_name, 
                    self.common_name, 'cn', message)
        if args.sslexpiry:
            self.check_expiry(args.sslexpiry, message)


class MeasurmentPing(Measurment):
    """Object for an atlas Ping Measurment"""

    def __init__(self, probe_id, payload):
        """Initiate object"""
        #super(Measurment, self).__init__(self, payload)
        Measurment.__init__(self, probe_id, payload)
        self.avg_rtt = self.payload[0]

    @staticmethod
    def add_args(subparser):
        """add SSL arguments"""
        parser = subparser.add_parser('ping', help='SSL check')
        Measurment.add_args(parser)
        parser.add_argument('--rtt_max',
                help='Ensure the max ttl is below this')
        parser.add_argument('--rtt_min',
                help='Ensure the min ttl is below this')
        parser.add_argument('--rtt_avg',
                help='Ensure the avg ttl is below this')

    def check_rtt(self, check_type, rtt, message):
        """Check the return trip time islower then rtt"""
        msg = "desierd (%s), real (%s)" % (rtt, self.avg_rtt)
        if self.avg_rtt < rtt:
            message.add_ok(self.msg % (
                    self.probe_id, msg, "Ping %s" % check_type))
        else:
            message.add_error(self.msg % (
                    self.probe_id, msg, "Ping %s" % check_type))

    def check(self, args, message):
        """Main ping check routine"""
        Measurment.check(self, args, message)

        if args.rtt_min:
            self.check_rtt("min", args.rtt_min, message) 
        if args.rtt_max:
            self.check_rtt("max", args.rtt_max, message) 
        if args.rtt_avg:
            self.check_rtt("avg", args.rtt_avg, message) 


class MeasurmentHTTP(Measurment):
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

    @staticmethod
    def add_args(subparser):
        """add SSL arguments"""
        parser = subparser.add_parser('http', help='SSL check')
        Measurment.add_args(parser)
        parser.add_argument('--status_code', type=int, default=200,
                help='Ensure the site returns this status code')

    def check_status(self, check_status, message):
        """check the HTTP status is the same as check_status"""
        msg = "%s: desierd (%s), real (%s)" % \
                (self.probe_id, check_status, self.status)
        try:
            if int(self.status) == int(check_status):
                message.add_ok(self.msg % (
                        self.probe_id, msg, "HTTP Status Code"))
            else:
                message.add_error(self.msg % (
                        self.probe_id, msg, "HTTP Status Code"))
        except ValueError:
            message.add_error(self.msg % (
                    self.probe_id, msg, "HTTP Status Code"))

    def check(self, args, message):
        """Main HTTP check routine"""
        Measurment.check(self, args, message)
        if args.status_code:
            self.check_status(args.status_code, message)


class AnswerDns:
    """Parent class to hold dns measuerment payloads"""

    def __init__(self, probe_id, answer):
        """Initiate object"""
        self.answer = answer
        self.probe_id = probe_id
        self.msg = "Probe (%s): %s (%s)" 
        try:
            if "RRSIG" == self.answer.split()[3]:
                self.rrtype = "RRSIG"
        except IndexError:
            print self.answer

    def check_string(self, check_type, 
            measurment_string, check_string, message):
        """Generic function to compare two strings"""
        if check_string == measurment_string:
            message.add_ok(self.msg % (
                    self.probe_id, check_type, measurment_string))
        else:
            message.add_error(
                    self.msg % (self.probe_id, check_type, measurment_string))

    def check(self, args, message):
        """Main Check routine"""
        raise NotImplementedError("Subclasses should implement this!")


class AnswerDnsSOA(AnswerDns):
    """Parent class to hold dns SOA measuerment payloads"""
    def __init__(self, probe_id, answer ):
        AnswerDns.__init__(self, probe_id, answer)
        try:
            if "SOA" == self.answer.split()[3]:
                self.qname, self.ttl, _,  self.rrtype, self.mname, \
                        self.rname, self.serial, self.refresh, self.update, \
                        self.expire, self.nxdomain = answer.split()
        except IndexError:
            print self.answer

    def check(self, args, message):
        """Main Check routine"""
        if self.rrtype == "RRSIG":
            return
        elif self.rrtype != "SOA":
            message.add_error(self.msg % (
                    self.probe_id, "RRTYPE", self.rrtype))
            return
        else:
            if args.mname:
                self.check_string("mname", 
                        self.mname, args.mname, message) 
            if args.rname:
                self.check_string("rname", 
                        self.rname, args.rname, message) 
            if args.serial:
                self.check_string("serial", 
                        self.serial, args.serial, message) 
            if args.refresh:
                self.check_string("refresh", 
                        self.refresh, args.refresh, message) 
            if args.update:
                self.check_string("update", 
                        self.update, args.update, message) 
            if args.expire:
                self.check_string("expire", 
                        self.expire, args.expire, message) 
            if args.nxdomain:
                self.check_string("nxdomain", 
                        self.nxdomain, args.nxdomain, message) 


class AnswerDnsA(AnswerDns):
    """Parent class to hold dns A measuerment payloads"""
    def __init__(self, probe_id, answer ):
        AnswerDns.__init__(self, probe_id, answer)
        try:
            if "A" == self.answer.split()[3]:
                self.qname, self.ttl, _, self.rrtype, \
                        self.rdata = answer.split()
            elif "CNAME" == self.answer.split()[3]:
                self.qname, self.ttl, _, self.rrtype, \
                        self.rdata = answer.split()
        except IndexError:
            print self.answer

    def check(self, args, message):
        """Main Check routine"""
        if self.rrtype == "RRSIG":
            return
        elif self.rrtype != "A" and self.rrtype != "CNAME":
            message.add_error(self.msg % (
                    self.probe_id, "RRTYPE", self.rrtype))
            return
        else:
            if args.cname_record and self.rrtype == "CNAME":
                self.check_string("cname", 
                        self.rdata, args.cname_record, message) 
            if args.a_record and self.rrtype == "A":
                self.check_string("a", 
                        self.rdata, args.a_record, message) 


class AnswerDnsAAAA(AnswerDns):
    """Parent class to hold dns A measuerment payloads"""
    def __init__(self, probe_id, answer ):
        AnswerDns.__init__(self, probe_id, answer)
        try:
            if "AAAA" == self.answer.split()[3]:
                self.qname, self.ttl, _, self.rrtype, \
                        self.rdata = answer.split()
            elif "CNAME" == self.answer.split()[3]:
                self.qname, self.ttl, _, self.rrtype, \
                        self.rdata = answer.split()
        except IndexError:
            print self.answer

    def check(self, args, message):
        """Main Check routine"""
        if self.rrtype == "RRSIG":
            return
        elif self.rrtype != "AAAA" and self.rrtype != "CNAME":
            message.add_error(self.msg % (
                    self.probe_id, "RRTYPE", self.rrtype))
            return
        else:
            if args.cname_record and self.rrtype == "CNAME":
                self.check_string("cname", 
                        self.rdata, args.cname_record, message) 
            if args.aaaa_record and self.rrtype == "AAAA":
                self.check_string("aaaa", 
                        self.rdata, args.aaaa_record, message) 


class AnswerDnsCNAME(AnswerDns):
    """Parent class to hold dns CNAME measuerment payloads"""
    def __init__(self, probe_id, answer ):
        AnswerDns.__init__(self, probe_id, answer)
        try:
            if "CNAME" == self.answer.split()[3]:
                self.qname, self.ttl, _, self.rrtype, \
                        self.rdata = answer.split()
        except IndexError:
            print self.answer

    def check(self, args, message):
        """Main Check routine"""
        if self.rrtype == "RRSIG":
            return
        elif self.rrtype != "CNAME":
            message.add_error(self.msg % (
                    self.probe_id, "RRTYPE", self.rrtype))
            return
        else:
            if args.cname_record:
                self.check_string("cname", 
                        self.rdata, args.cname_record, message) 
 

class AnswerDnsDNSKEY(AnswerDns):
    """Parent class to hold dns DNSKEY measuerment payloads"""
    def __init__(self, probe_id, answer ):
        AnswerDns.__init__(self, probe_id, answer)
        try:
            if "DNSKEY" == self.answer.split()[3]:
                self.qname, self.ttl, _, self.rrtype, \
                        self.rdata = answer.split()
        except IndexError:
            print self.answer

    def check(self, args, message):
        """Main Check routine"""
        if self.rrtype == "RRSIG":
            return
        elif self.rrtype != "DNSKEY":
            message.add_error(self.msg % (
                    self.probe_id, "RRTYPE", self.rrtype))
            return
        else:
            if args.cname_record:
                self.check_string("cname", 
                        self.rdata, args.cname_record, message) 
 

class AnswerDnsDS(AnswerDns):
    """Parent class to hold dns DS measuerment payloads"""
    def __init__(self, probe_id, answer ):
        AnswerDns.__init__(self, probe_id, answer)
        try:
            if "DS" == self.answer.split()[3]:
                self.qname, self.ttl, _, self.rrtype, self.keytag, \
                        self.algorithm, self.digest_type, \
                        self.digest = answer.split()
        except IndexError:
            print self.answer

    def check(self, args, message):
        """Main Check routine"""
        if self.rrtype == "RRSIG":
            return
        elif self.rrtype != "DS":
            message.add_error(self.msg % (
                    self.probe_id, "RRTYPE", self.rrtype))
            return
        else:
            if args.keytag:
                self.check_string("keytag", 
                        self.keytag, args.keytag, message) 
            if args.algorithm:
                self.check_string("algorithm", 
                        self.algorithm, args.algorithm, message) 
            if args.digest_type:
                self.check_string("digest", 
                        self.digest_type, args.digest_type, message) 
            if args.digest:
                self.check_string("digest", 
                        self.digest, args.digest, message) 
 

class MeasurmentDns(Measurment):
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
        self.answer = []
        if self.rcode == "NOERROR":
            self.answer_raw = ensure_list(self.payload[2]['answer'])

    def check_rcode(self, rcode, message):
        """Check the RCODE is the same as rcode"""
        msg = "desierd (%s), real (%s)" % ( rcode, self.rcode)
        if self.rcode == rcode:
            message.add_ok(self.msg % (
                    self.probe_id, msg, "DNS RCODE"))
        else:
            message.add_error(self.msg % (
                    self.probe_id, msg, "DNS RCODE"))

    def check_flags(self, flags, message):
        """Check the flags returned in the check are the same as flags"""
        for flag in flags.split(","):
            if flag in self.flags.split(): 
                message.add_ok(self.msg % (
                        self.probe_id, "Flag found", flag))
            else:
                message.add_error(self.msg % (
                        self.probe_id, "Flag Missing ", flag))

    def check(self, args, message):
        """Main Check routine"""
        Measurment.check(self, args, message)

        if args.rcode:
            self.check_rcode(args.rcode, message)
        if args.flags:
            self.check_flags(args.flags, message)


class MeasurmentDnsA(MeasurmentDns):
    """class for a dns A measuerment"""

    def __init__(self, probe_id, payload):
        """Initiate Object"""
        #super(Measurment, self).__init__(self, payload)
        MeasurmentDns.__init__(self, probe_id, payload)
        for ans in self.answer_raw:
            self.answer.append(AnswerDnsA(self.probe_id, ans))

    def check(self, args, message):
        a_record = False
        cname_record = False
        MeasurmentDns.check(self, args, message)
        for ans in self.answer:
            ans.check(args, message)
            if args.a_record and ans.rrtype == "A":
                a_record = True
            if args.cname_record and ans.rrtype == "CNAME":
                cname_record = True
        if args.a_record and not a_record:
            message.add_error(self.msg % (
                self.probe_id, "No A Records Found", ""))
        if args.cname_record and not cname_record:
            message.add_error(self.msg % (
                self.probe_id, "No CNAME Records Found", ""))


class MeasurmentDnsAAAA(MeasurmentDns):
    """class for a dns AAAA measuerment"""

    def __init__(self, probe_id, payload):
        """Initiate Object"""
        #super(Measurment, self).__init__(self, payload)
        MeasurmentDns.__init__(self, probe_id, payload)
        for ans in self.answer_raw:
            self.answer.append(AnswerDnsAAAA(self.probe_id, ans))

    def check(self, args, message):
        aaaa_record = False
        cname_record = False
        MeasurmentDns.check(self, args, message)
        for ans in self.answer:
            ans.check(args, message)
            if args.aaaa_record and ans.rrtype == "AAAA":
                aaaa_record = True
            if args.cname_record and ans.rrtype == "CNAME":
                cname_record = True
        if args.aaaa_record and not aaaa_record:
            message.add_error(self.msg % (
                self.probe_id, "No AAAA Records Found", ""))
        if args.cname_record and not cname_record:
            message.add_error(self.msg % (
                self.probe_id, "No CNAME Records Found", ""))


class MeasurmentDnsCNAME(MeasurmentDns):
    """class for a dns CNAME measuerment"""

    def __init__(self, probe_id, payload):
        """Initiate Object"""
        #super(Measurment, self).__init__(self, payload)
        MeasurmentDns.__init__(self, probe_id, payload)
        for ans in self.answer_raw:
            self.answer.append(AnswerDnsCNAME(self.probe_id, ans))

    def check(self, args, message):
        cname_record = False
        MeasurmentDns.check(self, args, message)
        for ans in self.answer:
            ans.check(args, message)
            if args.cname_record and ans.rrtype == "CNAME":
                cname_record = True
        if args.cname_record and not cname_record:
            message.add_error(self.msg % (
                self.probe_id, "No CNAME Records Found", ""))


class MeasurmentDnsDS(MeasurmentDns):
    """class for a dns DS measuerment"""

    def __init__(self, probe_id, payload):
        """Initiate Object"""
        #super(Measurment, self).__init__(self, payload)
        MeasurmentDns.__init__(self, probe_id, payload)
        for ans in self.answer_raw:
            self.answer.append(AnswerDnsDS(self.probe_id, ans))

    def check(self, args, message):
        MeasurementDns.check(self, args, message)
        for ans in self.answer:
            ans.check(args, message)

class MeasurementDnsDNSKEY(MeasurementDns):
    """class for a dns DNSKEY measurement"""

    def __init__(self, probe_id, payload):
        """Initiate Object"""
        MeasurementDns.__init__(self, probe_id, payload)
        for ans in self.answer_raw:
            self.answer.append(AnswerDnsDNSKEY(self.probe_id, ans))

    def check(self, args, message):
        MeasurementDns.check(self.args, message)
        for ans in self.answer:
            ans.check(args, message)

class MeasurmentDnsSOA(MeasurmentDns):
    """class for a dns SOA measuerment"""

    def __init__(self, probe_id, payload):
        """Initiate Object"""
        #super(Measurment, self).__init__(self, payload)
        MeasurmentDns.__init__(self, probe_id, payload)
        for ans in self.answer_raw:
            self.answer.append(AnswerDnsSOA(self.probe_id, ans))

    def check(self, args, message):
        MeasurmentDns.check(self, args, message)
        for ans in self.answer:
            ans.check(args, message)

 
class JsonRequest(urllib2.Request):
    '''Object to make a Json HTTP request'''
    def __init__(self, url):
        urllib2.Request.__init__(self, url)
        self.add_header("Content-Type", "application/json")
        self.add_header("Accept", "application/json")



def arg_parse():
    """Parse arguments"""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers( 
            title="Supported Measuerment types", dest='name')

    #measuerement types
    MeasurmentSSL.add_args(subparsers)
    MeasurmentPing.add_args(subparsers)
    MeasurmentHTTP.add_args(subparsers)
    parser_dns = subparsers.add_parser('dns', help='DNS check')

    #HTTP args
   #DNS args
    subparsers_dns = parser_dns.add_subparsers(
            title='Supported DNS checks', dest='name')
    parser_dns_a = subparsers_dns.add_parser('a', 
            help='a record check')
    parser_dns_aaaa = subparsers_dns.add_parser('aaaa', 
            help='aaaa record check')
    parser_dns_cname = subparsers_dns.add_parser('cname', 
            help='cname record check')
    parser_dns_ds = subparsers_dns.add_parser('ds', 
            help='ds record check')
    parser_dns_soa = subparsers_dns.add_parser('soa', 
            help='soa record check')

    #DNS A OPTIONS
    parser_dns_a.add_argument('-v', '--verbose', action='count',
            help='increase verbosity')
    parser_dns_a.add_argument("measurement_id", 
            help="Measuerment ID to check")
    parser_dns_a.add_argument('--max_measurement_age', type=int, default=30,
            help='The max age of a measuerment in unix time')
    parser_dns_a.add_argument('--flags',
            help='The max age of a measuerment in unix time')
    parser_dns_a.add_argument('--rcode',
            help='The max age of a measuerment in unix time')
    parser_dns_a.add_argument('--cname-record',
            help='Ensure the RR set from the answer \
                     contains a CNAME record with this string')
    parser_dns_a.add_argument('--a-record',
            help='Ensure the RR set from the answer \
                     contains a A record with this string')
    #DNS AAAA OPTIONS
    parser_dns_aaaa.add_argument('-v', '--verbose', action='count',
            help='increase verbosity')
    parser_dns_aaaa.add_argument("measurement_id", 
            help="Measuerment ID to check")
    parser_dns_aaaa.add_argument('--max_measurement_age', type=int, default=30,
            help='The max age of a measuerment in unix time')
    parser_dns_aaaa.add_argument('--flags',
            help='The max age of a measuerment in unix time')
    parser_dns_aaaa.add_argument('--rcode',
            help='The max age of a measuerment in unix time')
    parser_dns_aaaa.add_argument('--cname-record',
            help='Ensure the RR set from the answer \
                     contains a CNAME record with this string')
    parser_dns_aaaa.add_argument('--aaaa-record',
            help='Ensure the RR set from the answer \
                     contains a A record with this string')

    #DNS CNAME OPTIONS
    parser_dns_cname.add_argument('-v', '--verbose', action='count',
            help='increase verbosity')
    parser_dns_cname.add_argument("measurement_id", 
            help="Measuerment ID to check")
    parser_dns_cname.add_argument('--max_measurement_age', type=int, default=30,
            help='The max age of a measuerment in unix time')
    parser_dns_cname.add_argument('--flags',
            help='The max age of a measuerment in unix time')
    parser_dns_cname.add_argument('--rcode',
            help='The max age of a measuerment in unix time')
    parser_dns_cname.add_argument('--cname-record',
            help='Ensure the RR set from the answer \
                     contains a CNAME record with this string')

    #DNS DS OPTIONS
    parser_dns_ds.add_argument('-v', '--verbose', action='count',
            help='increase verbosity')
    parser_dns_ds.add_argument("measurement_id", 
            help="Measuerment ID to check")
    parser_dns_ds.add_argument('--max_measurement_age', type=int, default=30,
            help='The max age of a measuerment in unix time')
    parser_dns_ds.add_argument('--flags',
            help='The max age of a measuerment in unix time')
    parser_dns_ds.add_argument('--rcode',
            help='The max age of a measuerment in unix time')
    parser_dns_ds.add_argument('--keytag',
            help='Ensure the RR set from the answer \
                     contains a keytag record with this string')
    parser_dns_ds.add_argument('--algorithm',
            help='Ensure the RR set from the answer \
                     contains a algorithm record with this string')
    parser_dns_ds.add_argument('--digest_type',
            help='Ensure the RR set from the answer \
                     contains a digest type record with this string')
    parser_dns_ds.add_argument('--digest',
            help='Ensure the RR set from the answer \
                     contains a digest record with this string')


     #DNS SOA OPTIONS
    parser_dns_soa.add_argument('-v', '--verbose', action='count',
            help='increase verbosity')
    parser_dns_soa.add_argument("measurement_id", 
            help="Measuerment ID to check")
    parser_dns_soa.add_argument('--max_measurement_age', type=int, default=30,
            help='The max age of a measuerment in unix time')
    parser_dns_soa.add_argument('--flags',
            help='The max age of a measuerment in unix time')
    parser_dns_soa.add_argument('--rcode',
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
    message = Message(args.verbose)
    measurements =  get_measurements(args.measurement_id)
    parsed_measurements = parse_measurements(
            measurements, args.name, message)
    check_measurements(parsed_measurements, args, message)
    message.exit()


if __name__ == '__main__':
    main()
