#!/usr/bin/env python
import time, sys

class NagiosMessage:
    '''Object to store nagios messages'''
    def __init__(self, verbose):
        '''
        Initialise Object
        verbose is an interger indicating how Much information to return
        '''
        self.error = []
        self.warn = []
        self.ok = []
        self.verbose = verbose

    def add_error(self, message):
        '''Add an error message'''
        self.error.append(message)

    def add_warn(self, message):
        '''Add an warn message'''
        self.warn.append(message)

    def add_ok(self, message):
        '''Add an ok message'''
        self.ok.append(message)

    def exit(self):
        '''Parse the nagios_message and exit correctly for nagios'''
        if len(self.error) > 0:
            if self.verbose > 0:
                print "ERROR: %d: %s" % (len(self.error),
                        ", ".join(self.error))
            else:
                print "ERROR: %d" % len(self.error)
            sys.exit(2)
        elif len(self.warn) > 0:
            if self.verbose > 0:
                print "WARN: %d: %s" % (len(self.warn),
                        ", ".join(self.warn))
            else:
                print "WARN: %d" % len(self.warn)
            sys.exit(1)
        else:
            if self.verbose > 1:
                print "OK: %d: %s" % (len(self.ok),
                    ", ".join(self.ok))
            else:
                print "OK: %d zones working" % len(self.ok)
            sys.exit(0)

class Measurment: 
    '''Parent object for an atlas measurment'''

    def __init__(self, probe_id, payload):    
        '''Initiate generic message data''' 
        self.probe_id = probe_id
        self.payload = payload
        self.check_time = self.payload[1]
        self.msg = "Probe (%s): %s (%s)" 

    def check_measurement_age(self, max_age, nagios_message):
        '''Check if a measerment is fresh enough'''
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
        '''Generic check to compare two strings'''
        if check_string == measurment_string:
            nagios_message.add_ok(self.msg % \
                    (self.probe_id, check_type, measurment_string))
        else:
            nagios_message.add_error(self.msg % \
                     (self.probe_id, check_type, measurment_string))

    def check(self, nagios_args, nagios_message):             
        '''main check fucntion'''
        if 'max_measurement_age' in nagios_args:
            self.check_measurement_age(
                    nagios_args['max_measurement_age'], nagios_message)

class SSLcertMeasurment(Measurment):
    '''Object for an atlas SSL Measurment'''

    def __init__(self, probe_id, payload):
        '''Initiate object'''
        #super(Measurment, self).__init__(payload)
        Measurment.__init__(self, probe_id, payload)
        self.common_name = self.payload[2][0][0]
        self.expiry = time.mktime(
                time.strptime(self.payload[2][0][4],"%Y%m%d%H%M%SZ"))
        self.sha1 = self.payload[2][0][5]

    def check_expiry(self, warn_expiry, nagios_message):
        '''Check if the certificat is going to expire before warn_expiry'''
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

    def check(self, nagios_args, nagios_message):
        '''Main SSL check routine'''
        Measurment.check(self, nagios_args, nagios_message)
        if 'sha1hash' in nagios_args:
            self.check_string( nagios_args['sha1hash'], 
                    self.sha1, 'sha1hash', nagios_message)
        if 'common_name' in nagios_args:
            self.check_string( nagios_args['common_name'], 
                    self.common_name, 'cn', nagios_message)
        if nagios_args['check_expiry'] and 'warn_expiry' in nagios_args:
            self.check_expiry(nagios_args['warn_expiry'], nagios_message)

class PingMeasurment(Measurment):
    '''Object for an atlas Ping Measurment'''

    def __init__(self, probe_id, payload):
        '''Initiate object'''
        #super(Measurment, self).__init__(self, payload)
        Measurment.__init__(self, probe_id, payload)
        self.avg_rtt = self.payload[0]

    def check_rtt(self, check_type, rtt, nagios_message):
        '''Check the return trip time islower then rtt'''
        msg = "desierd (%s), real (%s)" % (rtt, self.avg_rtt)
        if self.avg_rtt < rtt:
            nagios_message.add_ok(self.msg % (
                    self.probe_id, msg, "Ping %s" % check_type))
        else:
            nagios_message.add_error(self.msg % (
                    self.probe_id, msg, "Ping %s" % check_type))

    def check(self, nagios_args, nagios_message):
        '''Main ping check routine'''
        Measurment.check(self, nagios_args, nagios_message)
        for check_type, rtt in nagios_args['rtt'].iteritems():
            self.check_rtt(check_type, rtt, nagios_message) 

class HttpMeasurment(Measurment):
    '''Object for an atlas HTTP Measurment'''

    def __init__(self, probe_id, payload):
        '''Initiate object'''
        #super(Measurment, self).__init__(self, payload)
        Measurment.__init__(self, probe_id, payload)
        try:
            self.status = self.payload[2][0]['res']
        except KeyError:
            #probably a time out, should use a better status code
            self.status = 500

    def check_status(self, check_status, nagios_message):
        '''check the HTTP status is the same as check_status'''
        msg = "%s: desierd (%s), real (%s)" % \
                (self.probe_id, check_status, self.status)
        if self.status == check_status:
            nagios_message.add_ok(self.msg % (
                    self.probe_id, msg, "HTTP Status Code"))
        else:
            nagios_message.add_error(self.msg % (
                    self.probe_id, msg, "HTTP Status Code"))

    def check(self, nagios_args, nagios_message):
        '''Main HTTP check routine'''
        Measurment.check(self, nagios_args, nagios_message)
        if 'status_code' in nagios_args:
            self.check_status(nagios_args['status_code'], nagios_message)

class DnsAnswer:
    '''Parent class to hold dns measuerment payloads'''

    def __init__(self, probe_id, answer):
        '''Initiate object'''
        self.answer = answer
        self.probe_id = probe_id
        self.msg = "Probe (%s): %s (%s)" 

    def check_string(self, check_type, 
            measurment_string, check_string, nagios_message):
        '''Generic function to compare two strings'''
        if check_string == measurment_string:
            nagios_message.add_ok(self.msg % (
                    self.probe_id, check_type, measurment_string))
        else:
            nagios_message.add_error(
                    self.msg % (self.probe_id, check_type, measurment_string))

    def check(self, nagios_args, nagios_message):
        '''Main Check routine'''
        raise NotImplementedError("Subclasses should implement this!")

class SoaAnswer(DnsAnswer):
    '''Parent class to hold dns SOA measuerment payloads'''
    def __init__(self, probe_id, answer ):
        DnsAnswer.__init__(self, probe_id, answer)
        if "SOA" in self.answer:
            self.qname, self.ttl, _,  self.rrtype, self.mname, \
                    self.rname, self.serial, self.refresh, self.update, \
                    self.expire, self.nxdomain = answer.split()
        else:
            #i think the only other posibility is CNAME?
            print self.answer
            _, _, _, self.rrtype, _ = self.answer.split(None, 5)

    def check(self, nagios_args, nagios_message):
        '''Main Check routine'''
        if self.rrtype != "SOA": 
            nagios_message.add_error(self.msg % (
                    self.probe_id, "Answer is not SOA", self.rrtype))
            return
        for check_type, value in nagios_args['soa'].iteritems():
            if value != None:
                self.check_string(check_type, value, 
                        getattr(self, check_type), nagios_message) 

class DnsMeasurment(Measurment):
    '''Parent class or a dns measuerment'''

    def __init__(self, probe_id, payload):
        '''Initiate Object'''
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
        '''Check the RCODE is the same as rcode'''
        msg = "desierd (%s), real (%s)" % ( rcode, self.rcode)
        if self.rcode == rcode:
            nagios_message.add_ok(self.msg % (
                    self.probe_id, msg, "DNS RCODE"))
        else:
            nagios_message.add_error(self.msg % (
                    self.probe_id, msg, "DNS RCODE"))

    def check_flags(self, flags, nagios_message):
        '''Check the flags returned in the check are the same as flags'''
        for flag in flags.split():
            if flag in self.flags.split(): 
                nagios_message.add_ok(self.msg % (
                        self.probe_id, "Flag found", flag))
            else:
                nagios_message.add_error(self.msg % (
                        self.probe_id, "Flag Missing ", flag))

    def check(self, nagios_args, nagios_message):
        '''Main Check routine'''
        Measurment.check(self, nagios_args, nagios_message)
        if 'rcode' in nagios_args:
            self.check_rcode(nagios_args['rcode'], nagios_message)
        if 'flags' in nagios_args:
            self.check_flags(nagios_args['flags'], nagios_message)

        if self.rcode == "NOERROR":
            self.answer.check(nagios_args, nagios_message)
