#!/usr/bin/env python
import argparse

from messages import ProbeMessage
from measurements import *
from dns_answers import *
from utils import get_response,get_measurements,check_measurements, parse_measurements

def arg_parse():
    """Parse arguments"""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(
            title="Supported Measuerment types", dest='name')

    #measuerement types
    MeasurmentSSL.add_args(subparsers)
    MeasurmentPing.add_args(subparsers)
    MeasurmentHTTP.add_args(subparsers)
    dns_parser = subparsers.add_parser('dns', help='DNS check')
    dns_subparsers = dns_parser.add_subparsers(
            title="Supported DNS Measuerment types", dest='name')
    MeasurmentDnsA.add_args(dns_subparsers)
    MeasurmentDnsAAAA.add_args(dns_subparsers)
    MeasurmentDnsCNAME.add_args(dns_subparsers)
    MeasurmentDnsDS.add_args(dns_subparsers)
    MeasurmentDnsDNSKEY.add_args(dns_subparsers)
    MeasurmentDnsSOA.add_args(dns_subparsers)

    return parser.parse_args()


def main():
    """main function"""
    args = arg_parse()
    message = ProbeMessage(args.verbose)
    measurements =  get_measurements(args.measurement_id, args.key)
    parsed_measurements = parse_measurements(
            measurements, args.name, message)
    check_measurements(parsed_measurements, args, message)
    message.exit(args)


if __name__ == '__main__':
    main()
