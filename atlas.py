import time

class Measurment: 
    def __init__(self, probe_id, payload):    
        self.probe_id = probe_id
        self.payload = payload
        self.check_time = self.payload[1]
        self.msg = "Probe (%s): %s (%s)" 

    def check_measurement_age(self, max_age, results):
        min_time = time.time() - max_age
        check_time_str = time.ctime(self.check_time)
        if self.check_time < min_time:
            results['error'].append(self.msg % (self.probe_id, "measurement to old", check_time_str))
        else:
            results['ok'].append(self.msg % (self.probe_id, "measurement fresh", check_time_str))

    def check_string(self, check_string, measurment_string, check_type, results):
        if check_string == measurment_string:
            results['ok'].append(self.msg % (self.probe_id, check_type, measurment_string))
        else:
            results['error'].append(self.msg % (self.probe_id, check_type, measurment_string))

    def check(self, nagios_args, results):             
        if 'max_measurement_age' in nagios_args:
            self.check_measurement_age(nagios_args['max_measurement_age'], results)

class SSLcertMeasurment(Measurment):
    def __init__(self, probe_id, payload):
        #super(Measurment, self).__init__(payload)
        Measurment.__init__(self, probe_id, payload)
        self.common_name = self.payload[2][0][0]
        self.expiry = time.mktime(time.strptime(self.payload[2][0][4],"%Y%m%d%H%M%SZ"))
        self.sha1 = self.payload[2][0][5]

    def check_expiry(self, warn_expiry, results):
        current_time = time.time()
        warn_time = current_time - (warn_expiry * 60 * 60 * 24)
        expiry_str = time.ctime(self.expiry)
        if self.expiry < current_time:
            results['error'].append(self.msg % (self.probe_id, "certificate expierd", expiry_str))
        elif self.expiry < warn_time:
            results['warn'].append(self.msg % (self.probe_id, "certificate expires soon", expiry_str))
        else:
            results['ok'].append(self.msg % (self.probe_id, "certificate expiry good", expiry_str))

    def check(self, nagios_args, results):
        Measurment.check(self, nagios_args, results)
        if 'sha1hash' in nagios_args:
            self.check_string(nagios_args['sha1hash'], self.sha1, 'sha1hash', results)
        if 'common_name' in nagios_args:
            self.check_string(nagios_args['common_name'], self.common_name, 'cn', results)
        if nagios_args['check_expiry'] and 'warn_expiry' in nagios_args:
            self.check_expiry(nagios_args['warn_expiry'], results)

class PingMeasurment(Measurment):
    def __init__(self, probe_id, payload):
        #super(Measurment, self).__init__(self, payload)
        Measurment.__init__(self, probe_id, payload)
        self.avg_rtt = self.payload[0]

    def check_rtt(self, check_type, rtt, results):
        msg = "desierd (%s), real (%s)" % (rtt, self.avg_rtt)
        if self.avg_rtt < rtt:
            results['ok'].append(self.msg % (self.probe_id, msg, "Ping %s" % check_type))
        else:
            results['error'].append(self.msg % (self.probe_id, msg, "Ping %s" % check_type))

    def check(self, nagios_args, results):
        Measurment.check(self, nagios_args, results)
        for check_type, rtt in nagios_args['rtt'].iteritems():
            self.check_rtt(check_type, rtt, results) 

class HttpMeasurment(Measurment):
    def __init__(self, probe_id, payload):
        #super(Measurment, self).__init__(self, payload)
        Measurment.__init__(self, probe_id, payload)
        try:
            self.status = self.payload[2][0]['res']
        except KeyError as error:
            #probably a time out, should use a better status code
            self.status = 500

    def check_status(self, check_status, results):
        msg = "%s: desierd (%s), real (%s)" % (self.probe_id, check_status, self.status)
        if self.status == check_status:
            results['ok'].append(self.msg % (self.probe_id, msg, "HTTP Status Code"))
        else:
            results['error'].append(self.msg % (self.probe_id, msg, "HTTP Status Code"))

    def check(self, nagios_args, results):
        Measurment.check(self, nagios_args, results)
        if 'status_code' in nagios_args:
            self.check_status(nagios_args['status_code'], results)

class DnsAnswer:
    def __init__(self, probe_id, answer):
        self.answer = answer
        self.probe_id = probe_id
        self.msg = "Probe (%s): %s (%s)" 

    def check_string(self, check_type, measurment_string, check_string, results):
        if check_string == measurment_string:
            results['ok'].append(self.msg % (self.probe_id, check_type, measurment_string))
        else:
            results['error'].append(self.msg % (self.probe_id, check_type, measurment_string))

    def check(self, nagios_args, results):
        raise NotImplementedError("Subclasses should implement this!")

class SoaAnswer(DnsAnswer):
    def __init__(self, probe_id, answer):
        DnsAnswer.__init__(self, probe_id, answer)

        if "SOA" in self.answer:
            self.qname, self.ttl, _,  self.rrtype, self.mname, self.rname, self.serial, self.refresh, \
                self.update, self.expire, self.nxdomain = answer.split()
        else:
            #i think the only other posibility is CNAME?
            _, _, _, self.rrtype, _ = self.answer.split(None,5)

    def check(self, nagios_args, results):
        if self.rrtype != "SOA": 
            results['error'].append(self.msg % (self.probe_id, "Answer is not SOA", self.rrtype))
            return
        for check_type, value in nagios_args['soa'].iteritems():
            if value != None:
                self.check_string(check_type, value, getattr(self, check_type), results) 

class DnsMeasurment(Measurment):
    def __init__(self, probe_id, payload):
        #super(Measurment, self).__init__(self, payload)
        Measurment.__init__(self, probe_id, payload)
        self.additional = self.payload[2]['additional']
        self.question = { 'qname': "", 'qtype': "", 'question':"" }
        self.question['qname'], _, self.question['qtype'] = self.payload[2]['question'].split()
        self.authority = self.payload[2]['authority']
        self.rcode = self.payload[2]['rcode']
        self.flags = self.payload[2]['flags']
        self.answer = {
            "SOA": SoaAnswer,
        }.get(self.question['qtype'], DnsAnswer)(self.probe_id, self.payload[2]['answer'])

    def check_rcode(self, rcode, results):
        msg = "desierd (%s), real (%s)" % ( rcode, self.rcode)
        if self.rcode == rcode:
            results['ok'].append(self.msg % (self.probe_id, msg, "DNS RCODE"))
        else:
            results['error'].append(self.msg % (self.probe_id, msg, "DNS RCODE"))
    def check_flags(self, flags, flag_requierd, resultsi):
        if flag_requierd not in flags:
            msg = "Missing flag: %s" % ( flag_requierd)
            print msg

    def check(self, nagios_args, results):
        Measurment.check(self, nagios_args, results)
        if 'rcode' in nagios_args:
            self.check_rcode(nagios_args['rcode'], results)
        if 'flags' in nagios_args:
            for flag in nagios_args['flags'].split():
                if flag in self.flags.split(): 
                    results['ok'].append(self.msg % (self.probe_id, "Flag found", flag))
                else:
                    results['error'].append(self.msg % (self.probe_id, "Flag Missing ", flag))

        self.answer.check(nagios_args, results)
