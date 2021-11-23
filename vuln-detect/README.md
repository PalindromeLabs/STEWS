# STEWS Vulnerability Detection Tool

The STEWS (Security Tool for Enumerating WebSockets) vulnerability detection
tool allows users to test whether a WebSockets endpoint is vulnerable to known
CVEs or other WebSockets vulnerabilities.

The tool currently supports tests for vulnerabilities including:
- CSWSH (Cross-Site WebSocket Hijacking)
- CVE-2020-27813 (Gorilla DoS Integer Overflow)
- CVE-2020-7662 & CVE-2020-7663 (faye Sec-WebSocket-Extensions Regex DoS)
- CVE-2021-32640 (ws Sec-Websocket-Protocol Regex DoS)

A more complete list of CVEs that this tool might support in the future
can be found in the
[Awesome WebSocket Security repository](https://github.com/PalindromeLabs/awesome-websocket-security).

## Basic Usage

First, make sure you have the necessary Python 3 dependencies installed using
`pip3 install -r requirements.txt`. Then if you run
`python3 STEWS-vuln-detect.py -h` you will be greeted by the following options:

```
usage: STEWS-vuln-detect.py [-h] [-v] [-d] [-u URL] [-f FILE] [-n] [-k] [-o ORIGIN] [-1] [-2] [-3] [-4]

Security Testing and Enumeration of WebSockets (STEWS) Vulnerability Detection Tool

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbose tracing of communications
  -d, --debug           Print each test case to track progress while running
  -u URL, --url URL     URL to connect to
  -f FILE, --file FILE  File containing URLs to check for valid WebSocket connections
  -n, --no-encryption   Connect using ws://, not wss:// (default is wss://)
  -k, --nocert          Ignore invalid SSL cert
  -o ORIGIN, --origin ORIGIN
                        Set origin
  -1                    Test for generic Cross-site WebSocket Hijacking (CSWSH)
  -2                    Test CVE-2021-32640 - ws Sec-Websocket-Protocol Regex DoS
  -3                    Test CVE-2020-7662 & 7663 - faye Sec-WebSocket-Extensions Regex DoS
  -4                    Test CVE-2020-27813 - Gorilla DoS Integer Overflow
```

Test 1 provides a generic CSWSH test. This can be used in combination with the
`-o` flag to specify a specific origin to attempt to bypass any server-side checks.

Tests 2, 3, and 4 check for specific CVEs. The test cases for these were created
based on the PoC code published as part of the discovery of these CVEs. For example,
to run test 4 on a local server on port 8084, you can run:
`python3 STEWS-vuln-detect.py -4 -n -u 127.0.0.1:8084`

## Areas for future work

1. Add additional CVE detection tests based on list of CVEs in [Awesome WebSocket Security repository](https://github.com/PalindromeLabs/awesome-websocket-security)
2. Add test for [WebSocket smuggling](https://github.com/0ang3el/websocket-smuggle)
3. Add tests for misconfigurations (e.g. WebSocket protocol JSON input issues)
