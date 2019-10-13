#!/usr/bin/env python3
#
# Copyright (C) 2018 Daniel Stirnimann (daniel.stirnimann@switch.ch)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import argparse
import logging
import dns.query
import dns.exception
import dns.resolver
import dns.message
import dns.rrset
import dns.rdatatype
import dns.name
import dns.rcode
import dns.flags

# error response output
err_invalid = "Invalid response from server"
err_timeout = "No response from server (timeout)"


def get_ns_addresses(zoneorigin):
    """ returns unique authoritative ip addresses of all name servers
        for zoneorigin """
    # set up resolver: we use default system resolver
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout

    ns_name = []
    ns_addr = set()
    answer = resolver.query(zoneorigin, "NS", raise_on_no_answer=False)
    # we don't check additional section as local resolver could respond
    # with "minimal response" enabled
    if answer.rdtype == dns.rdatatype.NS and answer.rrset != None:
        for rrset in answer:
            ns_name.append( rrset.target.to_text().lower() )
    for ns in ns_name:
        answer_a = resolver.query(ns, "A", raise_on_no_answer=False) 
        for rrset in answer_a:
            ns_addr.add( rrset.address.lower() )
        answer_aaaa = resolver.query(ns, "AAAA", raise_on_no_answer=False) 
        for rrset in answer_aaaa:
            ns_addr.add( rrset.address.lower() )

    return ns_addr

def make_auth_query(address, request, isudp=True):
    """ Returns a multi-line string of all sorted RRsets from:
         - question section: case-preserved complete RR
         - answer, authority section:
               lowercased, each RR consists of owner name
               rdtype and rdata but not class or ttl
    """
    max_retry = 2 # 2 means 3 attempts in total
    retry = 0
    # default result if an invalid response received
    result = err_invalid

    while (retry < max_retry):
        try:
            if isudp:
                proto = "udp"
                response = dns.query.udp(request, address, timeout=timeout)
            else:
                proto = "tcp"
                response = dns.query.tcp(request, address, timeout=timeout)
            rrsetlist = []
            # RRsets within answer, authority section are sorted as not all server
            # respond RRset in same order (e.g. NSEC3). In addition, we sort
            # each RR within an RRset as server typically randomize them.
            if response.question:
                for rrset in response.question:
                    # question section is always case-sensitive
                    rrsetlist.append(rrset.to_text())

            if response.answer:
                for rrset in response.answer:
                    rrlist = []
                    for rr in rrset:
                        if casesensitive:
                            rrlist.append(rrset.name.to_text() + " "
                                + dns.rdatatype.to_text(rrset.rdtype) + " "
                                + rr.to_text())
                        else:
                            rrlist.append(rrset.name.to_text().lower() + " "
                                + dns.rdatatype.to_text(rrset.rdtype).lower() + " "
                                + rr.to_text().lower())
                    rrsetlist.append("\n".join(sorted(rrlist)))

            if response.authority:
                for rrset in response.authority:
                    rrlist = []
                    for rr in rrset:
                        if casesensitive:
                            rrlist.append(rrset.name.to_text() + " "
                                + dns.rdatatype.to_text(rrset.rdtype) + " "
                                + rr.to_text())
                        else:
                            rrlist.append(rrset.name.to_text().lower() + " "
                                + dns.rdatatype.to_text(rrset.rdtype).lower() + " "
                                + rr.to_text().lower())
                    rrsetlist.append("\n".join(sorted(rrlist)))

            if response.answer or response.authority:
                # break query while-loop as we got a response
                retry = max_retry
                result = "\n".join(sorted(rrsetlist))

        except dns.exception.Timeout as e:
            retry += 1
            result = err_timeout
            logging.debug("error for dns query to " + address + " (" + proto + "): " + str(e))
        except BrokenPipeError as e:
            retry += 1
            result = err_timeout
            logging.debug("error for dns query to " + address + " (" + proto + "): " + str(e))
        except Exception as e:
            retry += 1
            logging.debug("error for dns query to " + address + " (" + proto + "): " + str(e))

    return result


def make_test(ns_addr, qname):
    """ executes test for qname and returns list with two items where
        first item is boolean status code 0|1 and second item test result string
    """
    request = dns.message.make_query(qname, dns.rdatatype.A, use_edns=0, want_dnssec=1, payload=1232)
    result = dict()
    statuscode = False # False (0) = success, True (1) = error
    statustext = ""
    
    for addr in ns_addr:
        result[addr + "-udp"] = make_auth_query(addr, request)
        result[addr + "-tcp"] = make_auth_query(addr, request, isudp=False)

    unique_responses = list(set(result.values()))
    if len(unique_responses) == 1:
        # check if not all responses are bad
        if err_invalid in unique_responses or \
           err_timeout in unique_responses:
            statuscode = True
            statustext += "Test " + qname + ": BAD\n"
        else:
            statustext += "Test " + qname + ": OK\n"
    else:
        if ignoretimeout:
            unique_responses_copy = unique_responses.copy()
            unique_responses_copy.remove(err_timeout)
            if len(unique_responses_copy) == 1:
                # if all OK except some timeout and we ignore timeout then it is still OK!
                statustext += "Test " + qname + ": OK (ignoring timeout)\n"
            else:
                statuscode = True
                statustext += "Test " + qname + ": BAD\n"
        else:
            # if any result is bad, we change the overall status code
            statuscode = True
            statustext += "Test " + qname + ": BAD\n"
    for response in unique_responses:
        addrlist = []
        for addr, value in result.items():
            if response == value:
                addrlist.append(addr)
        statustext += str(len(addrlist)) + " responses from " + ", ".join(addrlist)
        statustext += " are:\n" + response + "\n"

    return [statuscode, statustext]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Nameserver response checker')
    parser.add_argument("-z", metavar="zone", required=True,
        help="zone name e.g. ch")
    parser.add_argument("-d", metavar="domain", nargs="+", required=True,
        help="test domain name(s). make use of 0x20 bit encoding, dnssec signed (e.g. Switch.ch), non-dnssec signed (e.g. noDnsSec.ch) and nxdomain response (e.g. YOURrandomSTRING.ch.)")
    parser.add_argument("-t", action='store_true', default=False,
        help="ignore no reponse (timeout)")
    parser.add_argument("-i", action='store_true', default=False,
        help="perform case sensitive matching (useful for testing only)")
    parser.add_argument("-v", action='store_true', default=False,
        help="verbose output")
    args = parser.parse_args()

    verbose = args.v
    casesensitive = args.i
    zoneorigin = args.z
    ignoretimeout = args.t

    if not zoneorigin.endswith("."):
        zoneorigin = zoneorigin + "."

    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    testdomains = []
    for domain in args.d:
        if not domain.endswith("."):
            domain = domain + "."
        if not domain.lower().endswith(zoneorigin.lower()):
            print("Error: %s must be a subdomain of %s" % (domain, zoneorigin))
            sys.exit(1)
        testdomains.append(domain)

    # defaults
    timeout = 2.0

    # get all ip addresses from authoritative name servers for zone origin
    ns_addr = get_ns_addresses(zoneorigin)

    # make test and construct result text
    result_error = False
    result_text = ""
    for test in testdomains:
        status = make_test(ns_addr, test) 
        result_text += status[1] + "\n"
        if status[0] == True:
            result_error = status[0]

    # print monitoring result
    if result_error:
        print("BAD - Some responses are different\n\n" + result_text)
        sys.exit(2)
    else:
        print("OK - All responses are identical\n\n" + result_text)
        sys.exit(0)
