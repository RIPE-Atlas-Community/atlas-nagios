import sys
import time
import argparse
import requests
import json
import pprint

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

    def str_message(self, probe_messages):
        return ', '.join(['%s=%s' % (key, value) for (key, value) in probe_messages.items()])

    def exit(self):
        """Parse the message and exit correctly for nagios"""
        if len(self.error) > 0:
            if self.verbose > 0:
                print "ERROR: %d: %s" % (len(self.error), self.str_message(self.error))
                if self.verbose > 1:
                    print "WARN: %d: %s" % (len(self.warn), self.str_message(self.warn))
                    print "OK: %d: %s" % (len(self.ok), self.str_message(self.ok))

            else:
                print "ERROR: %d" % len(self.error)
            sys.exit(2)
        elif len(self.warn) > 0:
            if self.verbose > 0:
                print "WARN: %d: %s" % (len(self.warn), self.str_message(self.warn))
                if self.verbose > 1:
                    print "OK: %d: %s" % (len(self.ok), self.str_message(self.ok))
            else:
                print "WARN: %d" % len(self.warn)
            sys.exit(1)
        else:
            if self.verbose > 1:
                print "OK: %d: %s" % (len(self.ok), self.str_message(self.ok))
            else:
                print "OK: %d" % len(self.ok)
            sys.exit(0)

class ProbeMessage:
    """Object to store nagios messages"""
    def __init__(self, verbose):
        """
        Initialise Object
        verbose is an interger indicating how Much information to return
        """
        #need to group these by probe id
        self.error = dict()
        self.warn = dict()
        self.ok = dict()
        self.verbose = verbose

    def add_error(self, probe, message):
        """Add an error message"""
        try:
            self.error[probe].append(message)
        except KeyError:
            self.error[probe] = [message]

    def add_warn(self, probe, message):
        """Add an warn message"""
        try:
            self.warn[probe].append(message)
        except KeyError:
            self.warn[probe] = [message]

    def add_ok(self, probe, message):
        """Add an ok message"""
        try:
            self.ok[probe].append(message)
        except KeyError:
            self.ok[probe] = [message]

    def str_message(self, probe_messages):
        return ', '.join(['%s=%s' % (key, value) for (key, value) in probe_messages.items()])

    def exit(self, args):
        """Parse the message and exit correctly for nagios"""
        if len(self.error) > args.crit_probes:
            if self.verbose > 0:
                print "ERROR: %d: %s" % (len(self.error), self.str_message(self.error))
                if self.verbose > 1:
                    print "WARN: %d: %s" % (len(self.warn), self.str_message(self.warn))
                    print "OK: %d: %s" % (len(self.ok), self.str_message(self.ok))

            else:
                print "ERROR: %d" % len(self.error)
            sys.exit(2)
        elif len(self.warn) > args.warn_probes:
            if self.verbose > 0:
                print "WARN: %d: %s" % (len(self.warn), self.str_message(self.warn))
                if self.verbose > 1:
                    print "OK: %d: %s" % (len(self.ok), self.str_message(self.ok))
            else:
                print "WARN: %d" % len(self.warn)
            sys.exit(1)
        else:
            if self.verbose > 1:
                print "OK: %d: %s" % (len(self.ok), self.str_message(self.ok))
            else:
                print "OK: %d" % len(self.ok)
            sys.exit(0)

