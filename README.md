# authserver-check
Given a zone name, the script enummerates all authoritative name server IP addresses and then queries them all with a set of test queries over UDP/TCP and checks if all responses are identical. The usefulness of this check relies on the query test domain names. It is recommended to use at least three test query domain names with the following properties:

 * test DNSSEC signed delegation response
 * test non-DNSSEC signed delegation response
 * test non-existing domain (NXDOMAIN) response

and finally, make use of 0x20 bit encoding in query names.

Responses are identical if the question, answer and authority section including any DNSSEC resource records such as RRSIG or NSEC(3) are identical. Authority and additional section can vary among implementations (e.g. minimal response). For this reason, additional section is ignored and one should choose test query domain names which are either delegations or NXDOMAIN responses so that authority section is consistent.

The check assumes that zone synchronization is working. The SOA serial number should be consistent among all authoritative name servers. To avoid occasional false positives one can delay alert notifications by the monitoring system by a few minutes. If the zone is DNSSEC signed using Online Signing and makes use of elliptic curve DNSSEC algorithms, then RRSIGs will differ on each server and the check cannot be used.

The script has been tested with Nagios/Check-MK. It uses the exit code to signal the test result:
 * sys.exit(0) -> OK
 * sys.exit(1) -> Warning
 * sys.exit(2) -> CRITICAL

## Dependencies
 * [python3](https://www.python.org/)
 * [dnspython](http://www.dnspython.org/)

If you have installed python you should be able to install dnsypthon with the command `pip3`:
```
pip3 install dnspython
```

## Usage

```
./check-authserver.py -h
usage: check-authserver.py [-h] -z zone -d domain [domain ...] [-i] [-v]

Nameserver response checker

optional arguments:
  -h, --help            show this help message and exit
  -z zone               zone name e.g. ch
  -d domain [domain ...]
                        test domain name(s). make use of 0x20 bit encoding,
                        dnssec signed (e.g. Switch.ch), non-dnssec signed
                        (e.g. noDnsSec.ch) and nxdomain response (e.g.
                        YOURrandomSTRING.ch.)
  -i                    perform case sensitive matching (useful for testing
                        only)
  -v                    verbose output
```

Notes:
 * The script sends DNS queries to your local resolver but also to authoritative name servers directly

## License
Licensed under the term of [MIT License](https://en.wikipedia.org/wiki/MIT_License).
