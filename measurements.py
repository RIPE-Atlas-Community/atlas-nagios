import sys
import time
import argparse
import requests
import json
import pprint
from dns_answers import AnswerDnsA, AnswerDnsAAAA, AnswerDnsCNAME, AnswerDnsDS, AnswerDnsDNSKEY, AnswerDnsSOA

class Measurment:
    """Parent object for an atlas measurment"""

    def __init__(self, probe_id, payload):
        """Initiate generic message data"""
        self.probe_id = probe_id
        self.payload = payload
        self.check_time = self.payload['timestamp']
        self.result = self.payload['result']
        self.msg = "%s (%s)"

    @staticmethod
    def add_args(parser):
        """add SSL arguments"""
        parser.add_argument('-v', '--verbose', action='count',
                help='Increase verbosity')
        parser.add_argument("measurement_id",
                help="Measuerment ID to check")
        parser.add_argument('-w', '--warn-probes', type=int, default=2,
                help='WARN if # probes have a warn condition')
        parser.add_argument('-c', '--crit-probes', type=int, default=1,
                help='ERROR if # probes have a warn condition')
        parser.add_argument('-k', '--key',
                help="API key for non-public measurements")
        parser.add_argument('--max_measurement_age', type=int, default=3600,
                help='The max age of a measuerment in seconds')

    def ensure_list(self, list_please):
        """make @list_please a list if it isn't one already"""
        if type(list_please) != list:
            return [(list_please)]
        else:
            return list_please

    def check_measurement_age(self, max_age, message):
        """Check if a measerment is fresh enough"""
        min_time = time.time() - max_age
        check_time_str = time.ctime(self.check_time)
        if self.check_time < min_time:
            message.add_error(self.probe_id, self.msg % \
                    ("measurement to old", check_time_str))
        else:
            message.add_ok(self.probe_id, self.msg % \
                    ("measurement fresh", check_time_str))

    def check_string(self, check_string, measurment_string,
            check_type, message):
        """Generic check to compare two strings"""
        if check_string == measurment_string:
            message.add_ok(self.probe_id, self.msg % \
                    (check_type, measurment_string))
        else:
            message.add_error(self.probe_id, self.msg % \
                     (check_type, measurment_string))

    def check(self, args, message):
        """main check fucntion"""
        self.check_measurement_age(args.max_measurement_age, message)


class MeasurmentSSL(Measurment):
    """Object for an atlas SSL Measurment"""

    def __init__(self, probe_id, payload):
        """Initiate object"""
        #super(Measurment, self).__init__(payload)
        Measurment.__init__(self, probe_id, payload)
        self.common_name = self.result[0][0]
        self.expire = time.mktime(
                time.strptime(self.result[0][4],"%Y%m%d%H%M%SZ"))
        self.sha1 = self.result[0][5]

    @staticmethod
    def add_args(subparser):
        """add SSL arguments"""
        parser = subparser.add_parser('ssl', help='SSL check')
        Measurment.add_args(parser)
        parser.add_argument('--common-name',
                help='Ensure a cert has this cn')
        parser.add_argument('--ssl-expire-days', type=int, default=30,
                help="Ensure certificate dosne't expire in x days")
        parser.add_argument('--sha1hash',
                help="Ensure certificate has this sha1 hash")

    def check_expiry(self, warn_expiry, message):
        """Check if the certificat is going to expire before warn_expiry"""
        current_time = time.time()
        warn_time = current_time + (warn_expiry * 60 * 60 * 24)
        expire_str = time.ctime(self.expire)
        if self.expire < current_time:
            message.add_error(self.probe_id, self.msg % (
                    "certificate expierd", expire_str))
            return
        elif self.expire < warn_time:
            message.add_warn(self.probe_id, self.msg % (
                    "certificate expires soon", expire_str))
        else:
            message.add_ok(self.probe_id, self.msg % (
                    "certificate expiry good", expire_str))

    def check(self, args, message):
        """Main SSL check routine"""
        Measurment.check(self, args, message)
        if args.sha1hash:
            self.check_string( args.sha1hash,
                    self.sha1, 'sha1hash', message)
        if args.common_name:
            self.check_string( args.common_name,
                    self.common_name, 'cn', message)
        if args.ssl_expire_days:
            self.check_expiry(args.ssl_expire_days, message)


class MeasurmentPing(Measurment):
    """Object for an atlas Ping Measurment"""

    def __init__(self, probe_id, payload):
        """Initiate object"""
        #super(Measurment, self).__init__(self, payload)
        Measurment.__init__(self, probe_id, payload)
        self.avg_rtt = self.payload['average']

    @staticmethod
    def add_args(subparser):
        """add SSL arguments"""
        parser = subparser.add_parser('ping', help='SSL check')
        Measurment.add_args(parser)
        parser.add_argument('--rtt-max', type=float,
                help='Ensure the max ttl is below this')
        parser.add_argument('--rtt-min', type=float,
                help='Ensure the min ttl is below this')
        parser.add_argument('--rtt-avg', type=float,
                help='Ensure the avg ttl is below this')

    def check_rtt(self, check_type, rtt, message):
        """Check the return trip time islower then rtt"""
        msg = "desired (%s), real (%s)" % (rtt, self.avg_rtt)
        if self.avg_rtt < float(rtt):
            message.add_ok(self.probe_id, self.msg % (
                     msg, "Ping %s" % check_type))
        else:
            message.add_error(self.probe_id, self.msg % (
                    msg, "Ping %s" % check_type))

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
            self.status = self.result[0]['res']
        except KeyError:
            try:
                self.status = self.result[0]['dnserr']
            except KeyError:
                #probably a time out, should use a better status code
                self.status = 500

    @staticmethod
    def add_args(subparser):
        """add SSL arguments"""
        parser = subparser.add_parser('http', help='SSL check')
        Measurment.add_args(parser)
        parser.add_argument('--status-code', type=int, default=200,
                help='Ensure the site returns this status code')

    def check_status(self, check_status, message):
        """check the HTTP status is the same as check_status"""
        msg = "desired (%s), real (%s)" % \
                (check_status, self.status)
        try:
            if int(self.status) == int(check_status):
                message.add_ok(self.probe_id, self.msg % (
                    msg, "HTTP Status Code"))
            else:
                message.add_error(self.probe_id, self.msg % (
                    msg, "HTTP Status Code"))
        except ValueError:
            message.add_error(self.probe_id, self.msg % (
                    msg, "HTTP Status Code"))

    def check(self, args, message):
        """Main HTTP check routine"""
        Measurment.check(self, args, message)
        if args.status_code:
            self.check_status(args.status_code, message)

class MeasurmentDns(Measurment):
    """Parent class for a dns measuerment"""

    def __init__(self, probe_id, payload):
        """Initiate Object"""
        #super(Measurment, self).__init__(self, payload)
        Measurment.__init__(self, probe_id, payload)
        self.additional = self.result['additional']
        self.question = { 'qname': '', 'qtype': '' }
        self.question['qname'], _, self.question['qtype'] = \
                self.result['question'].split()
        self.authority = self.result['authority']
        self.rcode = self.result['rcode']
        self.flags = self.result['flags']
        self.answer = []
        self.answer_raw = self.ensure_list(self.result['answer'])

    @staticmethod
    def add_args(parser):
        """add default dns args"""
        Measurment.add_args(parser)
        parser.add_argument('--flags',
                help='Comma seperated list of flags to expect')
        parser.add_argument('--rcode',
                help='rcode to expect')


    def check_rcode(self, rcode, message):
        """Check the RCODE is the same as rcode"""
        msg = "desired (%s), real (%s)" % ( rcode, self.rcode)
        if self.rcode == rcode:
            message.add_ok(self.probe_id, self.msg % (
                    msg, "DNS RCODE"))
        else:
            message.add_error(self.probe_id, self.msg % (
                    msg, "DNS RCODE"))

    def check_flags(self, flags, message):
        """Check the flags returned in the check are the same as flags"""
        for flag in flags.split(","):
            if flag in self.flags.split():
                message.add_ok(self.probe_id, self.msg % (
                        "Flag found", flag))
            else:
                message.add_error(self.probe_id, self.msg % (
                        "Flag Missing ", flag))

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
            if ans:
                self.answer.append(AnswerDnsA(self.probe_id, ans))

    @staticmethod
    def add_args(subparser):
        parser = subparser.add_parser('A', help='A DNS check')
        MeasurmentDns.add_args(parser)
        parser.add_argument('--cname-record',
                help='Ensure the RR set from the answer \
                        contains a CNAME record with this string')
        parser.add_argument('--a-record',
                help='Ensure the RR set from the answer \
                        contains a A record with this string')

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
            message.add_error(self.probe_id, self.msg % (
                "No A Records Found", ""))
        if args.cname_record and not cname_record:
            message.add_error(self.probe_id, self.msg % (
                "No CNAME Records Found", ""))


class MeasurmentDnsAAAA(MeasurmentDns):
    """class for a dns AAAA measuerment"""

    def __init__(self, probe_id, payload):
        """Initiate Object"""
        #super(Measurment, self).__init__(self, payload)
        MeasurmentDns.__init__(self, probe_id, payload)
        for ans in self.answer_raw:
            if ans:
                self.answer.append(AnswerDnsAAAA(self.probe_id, ans))

    @staticmethod
    def add_args(subparser):
        parser = subparser.add_parser('AAAA', help='AAAA DNS check')
        MeasurmentDns.add_args(parser)
        parser.add_argument('--cname-record',
                help='Ensure the RR set from the answer \
                        contains a CNAME record with this string')
        parser.add_argument('--aaaa-record',
                help='Ensure the RR set from the answer \
                        contains a A record with this string')


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
            message.add_error(self.probe_id, self.msg % (
                "No AAAA Records Found", ""))
        if args.cname_record and not cname_record:
            message.add_error(self.probe_id, self.msg % (
                "No CNAME Records Found", ""))


class MeasurmentDnsCNAME(MeasurmentDns):
    """class for a dns CNAME measuerment"""

    def __init__(self, probe_id, payload):
        """Initiate Object"""
        #super(Measurment, self).__init__(self, payload)
        MeasurmentDns.__init__(self, probe_id, payload)
        for ans in self.answer_raw:
            if ans:
                self.answer.append(AnswerDnsCNAME(self.probe_id, ans))

    @staticmethod
    def add_args(subparser):
        parser = subparser.add_parser('CNAME', help='CNAME DNS check')
        MeasurmentDns.add_args(parser)
        parser.add_argument('--cname-record',
                help='Ensure the RR set from the answer \
                        contains a CNAME record with this string')

    def check(self, args, message):
        cname_record = False
        MeasurmentDns.check(self, args, message)
        for ans in self.answer:
            ans.check(args, message)
            if args.cname_record and ans.rrtype == "CNAME":
                cname_record = True
        if args.cname_record and not cname_record:
            message.add_error(self.probe_id, self.msg % (
                "No CNAME Records Found", ""))


class MeasurmentDnsDS(MeasurmentDns):
    """class for a dns DS measuerment"""

    def __init__(self, probe_id, payload):
        """Initiate Object"""
        #super(Measurment, self).__init__(self, payload)
        MeasurmentDns.__init__(self, probe_id, payload)
        for ans in self.answer_raw:
            if ans:
                self.answer.append(AnswerDnsDS(self.probe_id, ans))

    @staticmethod
    def add_args(subparser):
        parser = subparser.add_parser('DS', help='CNAME DS check')
        MeasurmentDns.add_args(parser)
        parser.add_argument('--keytag',
                help='Ensure the RR set from the answer \
                        contains a keytag record with this string')
        parser.add_argument('--algorithm',
                help='Ensure the RR set from the answer \
                        contains a algorithm record with this string')
        parser.add_argument('--digest-type',
                help='Ensure the RR set from the answer \
                        contains a digest type record with this string')
        parser.add_argument('--digest',
                help='Ensure the RR set from the answer \
                        contains a digest record with this string')

    def check(self, args, message):
        MeasurmentDns.check(self, args, message)
        for ans in self.answer:
            ans.check(args, message)


class MeasurmentDnsDNSKEY(MeasurmentDns):
    """class for a dns DNSKEY measurement"""

    def __init__(self, probe_id, payload):
        """Initiate Object"""
        MeasurmentDns.__init__(self, probe_id, payload)
        for ans in self.answer_raw:
            if ans:
                self.answer.append(AnswerDnsDNSKEY(self.probe_id, ans))

    @staticmethod
    def add_args(subparser):
        parser = subparser.add_parser('DNSKEY', help='CNAME DNSKEY check')
        MeasurmentDns.add_args(parser)

    def check(self, args, message):
        MeasurmentDns.check(self, args, message)
        for ans in self.answer:
            ans.check(args, message)

class MeasurmentDnsSOA(MeasurmentDns):
    """class for a dns SOA measuerment"""

    def __init__(self, probe_id, payload):
        """Initiate Object"""
        #super(Measurment, self).__init__(self, payload)
        MeasurmentDns.__init__(self, probe_id, payload)
        for ans in self.answer_raw:
            if ans:
                self.answer.append(AnswerDnsSOA(self.probe_id, ans))

    @staticmethod
    def add_args(subparser):
        parser = subparser.add_parser('SOA', help='CNAME SOA check')
        MeasurmentDns.add_args(parser)
        parser.add_argument('--mname',
                help='Ensure the soa has this mname')
        parser.add_argument('--rname',
                help='Ensure the soa has this rname')
        parser.add_argument('--serial',
                help='Ensure the soa has this serial')
        parser.add_argument('--refresh',
                help='Ensure the soa has this refresh')
        parser.add_argument('--update',
                help='Ensure the soa has this update')
        parser.add_argument('--expire',
                help='Ensure the soa has this expire')
        parser.add_argument('--nxdomain',
                help='Ensure the soa has this nxdomain')

    def check(self, args, message):
        MeasurmentDns.check(self, args, message)
        for ans in self.answer:
            ans.check(args, message)
