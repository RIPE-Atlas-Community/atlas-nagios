import sys
import time
import argparse
import requests
import json
import pprint

class AnswerDns:
    """Parent class to hold dns measuerment payloads"""

    def __init__(self, probe_id, answer):
        """Initiate object"""
        self.answer = answer
        self.probe_id = probe_id
        self.msg = "%s (%s)"
        try:
            if "RRSIG" == self.answer.split()[3]:
                self.rrtype = "RRSIG"
        except IndexError:
            print self.answer

    @staticmethod
    def add_args(subparser):
        """add DNS arguments"""
        parser = subparser.add_parser('dns', help='SSL check')
        Measurment.add_args(parser)

    def check_string(self, check_type,
            measurment_string, check_string, message):
        """Generic function to compare two strings"""
        if check_string == measurment_string:
            message.add_ok(self.probe_id, self.msg % (
                    check_type, measurment_string))
        else:
            message.add_error(self.probe_id, self.msg % (
                check_type, measurment_string))

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
            message.add_error(self.probe_id, self.msg % (
                    "RRTYPE", self.rrtype))
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
            message.add_error(self.probe_id, self.msg % (
                    "RRTYPE", self.rrtype))
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
            message.add_error(self.probe_id, self.msg % (
                    "RRTYPE", self.rrtype))
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
            message.add_error(self.probe_id, self.msg % (
                    "RRTYPE", self.rrtype))
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
                        self.flags, self.protocol, self.algorithm, \
                        self.key = answer.split(' ',7)
        except IndexError:
            print self.answer

    def check(self, args, message):
        """Main Check routine"""
        if self.rrtype == "RRSIG":
            return
        elif self.rrtype != "DNSKEY":
            message.add_error(self.probe_id, self.msg % (
                    "RRTYPE", self.rrtype))
            return
        else:
            #not implmented
            return


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
            message.add_error(self.probe_id, self.msg % (
                    "RRTYPE", self.rrtype))
            return
        else:
            if args.keytag:
                self.check_string("keytag",
                        self.keytag, args.keytag, message)
            if args.algorithm:
                self.check_string("algorithm",
                        self.algorithm, args.algorithm, message)
            if args.digest_type:
                self.check_string("digest_type",
                        self.digest_type, args.digest_type, message)
            if args.digest:
                self.check_string("digest",
                        self.digest, args.digest, message)
