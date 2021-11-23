#!/usr/bin/env python

import argparse
import ssl
import time
import websocket
import requests
import socket
from cprint import *
from urllib.parse import urlparse

opcode_summary = []
close_summary = []
mask_summary = []
bad_input_summary = []
debug = False
cntn_timeout = 3
send_delay = 1


def parse_args():
    parser = argparse.ArgumentParser(description="Security Testing and Enumeration of WebSockets (STEWS) Fingerprinting Tool")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose tracing of communications")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Print each test case to track progress while running")
    parser.add_argument("-u", "--url",
                        help="Provide a URL to connect to")
    parser.add_argument("-f", "--file",
                        help="Provide a file containing URLs to check for valid WebSocket connections")
    parser.add_argument("-n", "--no-encryption", action="store_true",
                        help="Connect using ws://, not wss:// (default is wss://)")
    parser.add_argument("-k", "--nocert", action="store_true",
                        help="Ignore invalid SSL cert")
    parser.add_argument("-o", "--origin",
                        help="Set origin")
    parser.add_argument("-g", "--generate-fingerprint", action="store_true",
                        help="Generate a fingerprint for a known server")
    parser.add_argument("-a", "--all-tests", action="store_true",
                        help="Run all tests")
    parser.add_argument("-1", "--series-100", action="store_true",
                        help="Run the 100-series (opcode) tests")
    parser.add_argument("-2", "--series-200", action="store_true",
                        help="Run the 200-series (rsv bit) tests")
    parser.add_argument("-3", "--series-300", action="store_true",
                        help="Run the 300-series (version) tests")
    parser.add_argument("-4", "--series-400", action="store_true",
                        help="Run the 400-series (extensions) tests")
    parser.add_argument("-5", "--series-500", action="store_true",
                        help="Run the 500-series (subprotocols) tests")
    parser.add_argument("-6", "--series-600", action="store_true",
                        help="Run the 600-series (long payloads) tests")
    parser.add_argument("-7", "--series-700", action="store_true",
                        help="Run the 700-series (hybi and similar) tests")
    return parser.parse_args()


def print_opcode(opcode, recvdata):
    print("  >>opcode: ", websocket.ABNF.OPCODE_MAP[opcode])
    if opcode == websocket.ABNF.OPCODE_TEXT:
        print("  >>recvdata: ", recvdata.decode("utf-8"))
    else:
        print("  >>recvdata: ", recvdata)


def ws_reconnect(ws, wsurl, opts, options):
    try:
        ws.connect(wsurl, skip_utf8_validation=True, timeout=cntn_timeout, **options)
    except Exception as e:
        print("Exception while attempting reconnection: ", e)

################################
# Functions for series 100 tests
# Opcode field fingerprinting
################################


def opcode_send(ws, opcode):
    global debug
    time.sleep(send_delay)
    msg = "'"
    # Send an opcode. Return 1 if response received, 0 if not
    try:
        ws.send(msg, opcode)
        resp_opcode, resp_msg = ws.recv_data()
        if debug:
            print("   >>>SENT opcode ", str(opcode))
            print_opcode(resp_opcode, resp_msg)
        # NOTE: Some servers behind areverse proxy require a 2nd bad opcode message
        # to trigger a warning/error
        resp_opcode2 = ""
        resp_msg2 = ""
        try:
            ws.send(msg, opcode)
            resp_opcode2, resp_msg2 = ws.recv_data()
            if debug:
                print("   >>>SENT opcode ", str(opcode))
                print_opcode(resp_opcode2, resp_msg2)
            # Only use resp_msg2 and resp_opcode2 if resp_msg2 clearly contains an error message
            if list(bytes(resp_msg2))[0] == 3 and list(bytes(resp_msg2))[1] == 234:
                resp_opcode = resp_opcode2
                resp_msg = resp_msg2
        except Exception as e:
            print("Opcode " + websocket.ABNF.OPCODE_MAP[opcode] + " exception in secondary message: ", e)
        if len(resp_msg.decode('UTF8', 'ignore')) > 10:  # length of 10 is arbitrary, maybe should decrease
            return resp_msg
        else:
            return 1
    except Exception as e:
        print("Opcode " + websocket.ABNF.OPCODE_MAP[opcode] + " exception: ", e)
        return 0


# Send opcode value of 0x1 (text)
def test_100(ws, wsurl, opts, options):
    if debug:
        print("test 100")
    ws_reconnect(ws, wsurl, opts, options)
    return opcode_send(ws, websocket.ABNF.OPCODE_TEXT)


# Send opcode value of 0x2 (binary)
def test_101(ws, wsurl, opts, options):
    if debug:
        print("test 101")
    ws_reconnect(ws, wsurl, opts, options)
    return opcode_send(ws, websocket.ABNF.OPCODE_BINARY)


# Send opcode value of 0x9 (ping)
def test_102(ws, wsurl, opts, options):
    if debug:
        print("test 102")
    ws_reconnect(ws, wsurl, opts, options)
    return opcode_send(ws, websocket.ABNF.OPCODE_PING)


# Send opcode value of 0xa (pong)
def test_103(ws, wsurl, opts, options):
    if debug:
        print("test 103")
    ws_reconnect(ws, wsurl, opts, options)
    return opcode_send(ws, websocket.ABNF.OPCODE_PONG)


# Send opcode value of 0x0 (continue)
def test_104(ws, wsurl, opts, options):
    if debug:
        print("test 104")
    ws_reconnect(ws, wsurl, opts, options)
    return opcode_send(ws, websocket.ABNF.OPCODE_CONT)


# Send opcode value of 0xa (pong)
def test_105(ws, wsurl, opts, options):
    if debug:
        print("test 105")
    ws_reconnect(ws, wsurl, opts, options)
    return opcode_send(ws, websocket.ABNF.OPCODE_CLOSE)


def run_1xx_tests(ws, wsurl, opts, options):
    results_1xx = {}
    results_1xx['100'] = test_100(ws, wsurl, opts, options)
    results_1xx['101'] = test_101(ws, wsurl, opts, options)
    results_1xx['102'] = test_102(ws, wsurl, opts, options)
    results_1xx['103'] = test_103(ws, wsurl, opts, options)
    results_1xx['104'] = test_104(ws, wsurl, opts, options)
    results_1xx['105'] = test_105(ws, wsurl, opts, options)
    return results_1xx

################################
# Functions for series 200 tests
# Reserved bit fingerprinting
################################


def rsv_send(ws, rsv_bit1, rsv_bit2, rsv_bit3):
    global debug
    time.sleep(send_delay)
    msg = "'"
    fin = 1
    opcode = websocket.ABNF.OPCODE_BINARY
    # Reconnect in case connection is closed
    # Send opcode. Return 1 if response received, 0 if not
    try:
        rsv_frame = websocket.ABNF(fin, 0, 0, 1, opcode, 1, msg)
        ws.send_frame(rsv_frame)
        resp_opcode, resp_msg = ws.recv_data()
        if debug:
            print("   >>>SENT rsv bits " + str(rsv_bit1) + ", " + str(rsv_bit2) + ", " + str(rsv_bit3))
            print_opcode(resp_opcode, resp_msg)
        # NOTE: Some servers behind areverse proxy require a 2nd bad opcode message
        # to trigger a warning/error
        resp_opcode2 = ""
        resp_msg2 = ""
        try:
            ws.send_frame(rsv_frame)
            resp_opcode2, resp_msg2 = ws.recv_data()
            if debug:
                print("   >>>SENT rsv bits " + str(rsv_bit1) + ", " + str(rsv_bit2) + ", " + str(rsv_bit3))
                print_opcode(resp_opcode2, resp_msg2)
            if (list(bytes(resp_msg2))[0] == 3 and list(bytes(resp_msg2))[1] == 234) or len(resp_msg2) > len(resp_msg):
                resp_opcode = resp_opcode2
                resp_msg = resp_msg2
        except Exception as e:
            print("Opcode " + websocket.ABNF.OPCODE_MAP[opcode] + " exception in secondary message: ", e)
        if len(resp_msg.decode('UTF8', 'ignore')) > 10:  # limit of 10 is arbitrary
            return resp_msg
        else:
            return 1
    except Exception as e:
        print("rsv bits " + str(rsv_bit1) + ", " + str(rsv_bit2) + ", " + str(rsv_bit3) + " exception: ", e)
        return 0


def test_200(ws, wsurl, opts, options):
    if debug:
        print("test 200")
    ws_reconnect(ws, wsurl, opts, options)
    return rsv_send(ws, 0, 0, 1)


def test_201(ws, wsurl, opts, options):
    if debug:
        print("test 201")
    ws_reconnect(ws, wsurl, opts, options)
    return rsv_send(ws, 0, 1, 0)


def test_202(ws, wsurl, opts, options):
    if debug:
        print("test 202")
    ws_reconnect(ws, wsurl, opts, options)
    return rsv_send(ws, 0, 1, 1)


def test_203(ws, wsurl, opts, options):
    if debug:
        print("test 203")
    ws_reconnect(ws, wsurl, opts, options)
    return rsv_send(ws, 1, 0, 0)


def test_204(ws, wsurl, opts, options):
    if debug:
        print("test 204")
    ws_reconnect(ws, wsurl, opts, options)
    return rsv_send(ws, 1, 0, 1)


def test_205(ws, wsurl, opts, options):
    if debug:
        print("test 205")
    ws_reconnect(ws, wsurl, opts, options)
    return rsv_send(ws, 1, 1, 0)


def test_206(ws, wsurl, opts, options):
    if debug:
        print("test 206")
    ws_reconnect(ws, wsurl, opts, options)
    return rsv_send(ws, 1, 1, 1)


def run_2xx_tests(ws, wsurl, opts, options):
    results_2xx = {}
    results_2xx['200'] = test_200(ws, wsurl, opts, options)
    results_2xx['201'] = test_201(ws, wsurl, opts, options)
    results_2xx['202'] = test_202(ws, wsurl, opts, options)
    results_2xx['203'] = test_203(ws, wsurl, opts, options)
    results_2xx['204'] = test_204(ws, wsurl, opts, options)
    results_2xx['205'] = test_205(ws, wsurl, opts, options)
    results_2xx['206'] = test_206(ws, wsurl, opts, options)
    return results_2xx

################################
# Functions for series 300 tests
# Handshake Headers
################################


def version_try_connect(ws, ws_ver, wsurl, opts, options):
    msg = "'"
    options["header"] = {'Sec-WebSocket-Version': str(ws_ver)}
    try:
        ws_reconnect(ws, wsurl, opts, options)
        ws.send(msg)  # This results in an exception if connection was not established
        return 1
    except Exception as e:
        print("Exception while trying to connect for version: " + str(ws_ver), e)
        return 0


def pretty_print_GET(http_req):
    print('{}\n{}\r\n{}\r\n\r\n'.format(
        '-----------GET-----------',
        http_req.method + ' ' + http_req.url,
        '\r\n'.join('{}: {}'.format(key, val) for key, val in http_req.headers.items())))


def list_of_headers(ws, wsurl, opts, options):
    global debug
    headers = {'Upgrade': 'websocket', 'Origin': options["origin"], 'Sec-WebSocket-Key': 'U2NqiNJpRpRGdvagcfySUA==', 'Connection': 'Upgrade', 'Sec-WebSocket-Version': '13'}
    httpurl = ""
    # Convert ws:// URL to http:// URL
    if wsurl.find("wss://") >= 0:
        httpurl = wsurl.replace("wss://", "https://")
    elif wsurl.find("ws://") >= 0:
        httpurl = wsurl.replace("ws://", "http://")
    else:
        raise Exception("URL problem: no ws:// or wss://")
    # Prepare WebSocket handshake request
    req = requests.Request('GET',httpurl,headers=headers)
    prepared = req.prepare()
    if debug:
        pretty_print_GET(prepared)
    try:  # Try connecting to endpoint
        resp = requests.get(httpurl,headers=headers,timeout=cntn_timeout)
        if debug:
            print("Response headers: ", resp.headers)
        if resp.status_code == 101:
            return resp.headers
        else:
            cprint.err("Did not get a 101 status response for handshake request", interrupt=False)
            return []
    except Exception as e:
        print("Exception while trying to connect for subprotocol tests: ", e)
        return []


def header_evaluator(header_dict):
    for header_title, header_value in header_dict.items():
        if header_title.lower().find("uwebsockets") >= 0 or header_value.lower().find("uwebsockets") >= 0:
            return 1
        elif (header_title.lower().find("x-powered-by") >= 0 or header_title.lower().find("x_powered_by") >= 0) and \
            header_value.lower().find("ratchet") >= 0:
            return 2
        elif header_title.lower().find("server") >= 0 and \
            (header_value.lower().find("python") >= 0 or header_value.lower().find("websockets") >= 0):
            return 3
        elif header_title.lower().find("server") >= 0 and \
            (header_value.lower().find("tootallnate") >= 0 or header_value.lower().find("Java-WebSocket") >= 0):
            return 4
        elif header_title.lower().find("server") >= 0 and \
            (header_value.lower().find("boost") >= 0 or header_value.lower().find("beast") >= 0):
            return 5
        elif header_title.lower().find("x-powered-by") >= 0 and header_value.lower().find("ratchet") >= 0:
            return 6
    return 0


def test_300(ws, wsurl, opts, options):
    if debug:
        print("test 300")
    return version_try_connect(ws, 7, wsurl, opts, options)


def test_301(ws, wsurl, opts, options):
    if debug:
        print("test 301")
    return version_try_connect(ws, 8, wsurl, opts, options)


def test_302(ws, wsurl, opts, options):
    if debug:
        print("test 302")
    return version_try_connect(ws, "13;", wsurl, opts, options)


def test_303(ws, wsurl, opts, options):
    if debug:
        print("test 303")
    return version_try_connect(ws, "13,14,15", wsurl, opts, options)


def test_304(ws, wsurl, opts, options):
    if debug:
        print("test 304")
    return version_try_connect(ws, "13-", wsurl, opts, options)


def test_305(ws, wsurl, opts, options):
    if debug:
        print("test 305")
    return version_try_connect(ws, "13\n", wsurl, opts, options)


def test_306(ws, wsurl, opts, options):
    if debug:
        print("test 306")
    return version_try_connect(ws, "13\r", wsurl, opts, options)


def test_307(ws, wsurl, opts, options):
    if debug:
        print("test 307")
    return version_try_connect(ws, "13\\", wsurl, opts, options)


def test_308(ws, wsurl, opts, options):
    if debug:
        print("test 308")
    return version_try_connect(ws, "13\/", wsurl, opts, options)


def test_309(ws, wsurl, opts, options):
    if debug:
        print("test 309")
    all_headers = list_of_headers(ws, wsurl, opts, options)
    if len(all_headers) == 0:
        return 0
    else:
        return header_evaluator(all_headers)


def test_310(ws, wsurl, opts, options):
    if debug:
        print("test 310")
    if wsurl.lower().find("socket.io") >= 0 or wsurl.lower().find("socketio") >= 0:
        return 1
    else:
        return 0


def run_3xx_tests(ws, wsurl, opts, options):
    results_3xx = {}
    results_3xx['300'] = test_300(ws, wsurl, opts, options)
    results_3xx['301'] = test_301(ws, wsurl, opts, options)
    results_3xx['302'] = test_302(ws, wsurl, opts, options)
    results_3xx['303'] = test_303(ws, wsurl, opts, options)
    results_3xx['304'] = test_304(ws, wsurl, opts, options)
    results_3xx['305'] = test_305(ws, wsurl, opts, options)
    results_3xx['306'] = test_306(ws, wsurl, opts, options)
    results_3xx['307'] = test_307(ws, wsurl, opts, options)
    results_3xx['308'] = test_308(ws, wsurl, opts, options)
    results_3xx['309'] = test_309(ws, wsurl, opts, options)
    results_3xx['310'] = test_310(ws, wsurl, opts, options)
    return results_3xx

################################
# Functions for series 400 tests
# Extensions
################################


def extension_try_connect(ext, ws, wsurl, opts, options):
    headers = {'Upgrade': 'websocket', 'Origin': options["origin"], 'Sec-WebSocket-Key': 'U2NqiNJpRpRGdvagcfySUA==', 'Connection': 'Upgrade', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Extensions': ext}
    httpurl = ""
    # Replace the WebSocket URL with a HTTP URL
    if wsurl.find("wss://") >= 0:
        httpurl = wsurl.replace("wss://", "https://")
    else:
        httpurl = wsurl.replace("ws://", "http://")
    # Prepare WebSocket handshake request
    req = requests.Request('GET',httpurl,headers=headers)
    prepared = req.prepare()
    if debug:
        pretty_print_GET(prepared)
    try:  # Try connecting to endpoint
        resp = requests.get(httpurl,headers=headers,timeout=cntn_timeout)
        if debug:
            print("Response headers: ", resp.headers)
        if resp.status_code == 101:
            for header_title, header_value in resp.headers.items():
                if header_title.lower().find("sec-websocket-extensions") >= 0:
                    return header_value
            return 0
        else:
            cprint.err("Did not get a 101 status response for handshake request", interrupt=False)
            return -1
    except Exception as e:
        print("Exception while trying to connect for extension tests: ", e)
        return 0


def test_400(ws, wsurl, opts, options):
    if debug:
        print("test 400")
    ws_extensions = ['permessage-deflate', 'deflate-frame', 'bbf-usp-protocol', 'superspeed', 'colormode', 'client_max_window_bits', 'server_max_window_bits=10', 'mux', 'x-webkit-deflate-frame']
    return extension_try_connect(', '.join(ws_extensions), ws, wsurl, opts, options)


def test_401(ws, wsurl, opts, options):
    if debug:
        print("test 401")
    ws_extensions = ['permessage-deflate', 'deflate-frame', 'bbf-usp-protocol', 'superspeed', 'colormode', 'client_max_window_bits', 'server_max_window_bits=10', 'mux', 'x-webkit-deflate-frame']
    ws_extensions.reverse()
    return extension_try_connect(', '.join(ws_extensions), ws, wsurl, opts, options)


def test_402(ws, wsurl, opts, options):
    if debug:
        print("test 402")
    return extension_try_connect("permessage-deflate; client_max_window_bits", ws, wsurl, opts, options)


def test_403(ws, wsurl, opts, options):
    if debug:
        print("test 403")
    return extension_try_connect("permessage-deflate; client_max_window_bits; server_max_window_bits=7", ws, wsurl, opts, options)


def test_404(ws, wsurl, opts, options):
    if debug:
        print("test 404")
    return extension_try_connect("permessage-deflate; client_max_window_bits; server_max_window_bits=16", ws, wsurl, opts, options)


def test_405(ws, wsurl, opts, options):
    if debug:
        print("test 405")
    return extension_try_connect("permessage-deflate; client_max_window_bits; server_max_window_bits=08", ws, wsurl, opts, options)


def run_4xx_tests(ws, wsurl, opts, options):
    results_4xx = {}
    results_4xx['400'] = test_400(ws, wsurl, opts, options)
    results_4xx['401'] = test_400(ws, wsurl, opts, options)
    results_4xx['402'] = test_400(ws, wsurl, opts, options)
    results_4xx['403'] = test_400(ws, wsurl, opts, options)
    results_4xx['404'] = test_400(ws, wsurl, opts, options)
    results_4xx['405'] = test_400(ws, wsurl, opts, options)
    return results_4xx

################################
# Functions for series 500 tests
# Subprotocols
################################


def protocol_try_connect(protocol, ws, wsurl, opts, options):
    headers = {'Upgrade': 'websocket', 'Origin': options["origin"], 'Sec-WebSocket-Key': 'U2NqiNJpRpRGdvagcfySUA==', 'Connection': 'Upgrade', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Protocol': protocol}
    httpurl = ""
    # Replace the WebSocket URL with a HTTP URL
    if wsurl.find("wss://") >= 0:
        httpurl = wsurl.replace("wss://", "https://")
    else:
        httpurl = wsurl.replace("ws://", "http://")
    # Prepare WebSocket handshake request
    req = requests.Request('GET',httpurl,headers=headers)
    prepared = req.prepare()
    if debug:
        pretty_print_GET(prepared)
    try:  # Try connecting to endpoint
        resp = requests.get(httpurl,headers=headers,timeout=cntn_timeout)
        if debug:
            print("Response headers: ", resp.headers)
        if resp.status_code == 101:
            for header_title, header_value in resp.headers.items():
                if header_title.lower().find("sec-websocket-protocol") >= 0:
                    return header_value
            return 0
        else:
            cprint.err("Did not get a 101 status response for handshake request", interrupt=False)
            return -1
    except Exception as e:
        print("Exception while trying to connect for extension tests: ", e)
        return 0


def test_500(ws, wsurl, opts, options):
    if debug:
        print("test 500")
    subprotocol_list = ['MBWS.huawei.com','MBLWS.huawei.com','soap','wamp','v10.stomp','v11.stomp','v12.stomp','ocpp1.2','ocpp1.5','ocpp1.6','ocpp2.0','ocpp2.0.1','rfb','sip','notificationchannel-netapi-rest.openmobilealliance.org','wpcp','amqp','mqtt','jsflow','rwpcp','xmpp','ship','mielecloudconnect','v10.pcp.sap.com','msrp','v1.saltyrtc.org','TLCP-2.0.0.lightstreamer.com','bfcp','sldp.softvelum.com','opcua+uacp','opcua+uajson','v1.swindon-lattice+json','v1.usp','mles-websocket','coap','TLCP-2.1.0.lightstreamer.com','sqlnet.oracle.com','oneM2M.R2.0.json','oneM2M.R2.0.xml','oneM2M.R2.0.cbor','transit','2016.serverpush.dash.mpeg.org','2018.mmt.mpeg.org','clue','webrtc.softvelum.com','cobra.v2.json','drp','hub.bsc.bacnet.org','dc.bsc.bacnet.org','jmap','t140','done','TLCP-2.2.0.lightstreamer.com','collection-update','zap-protocol-v1','chat','superchat','echo-protocol','graphql-ws','graphql-transport-ws','null','webtty','ISYSUB']
    return protocol_try_connect(",".join(map(str, subprotocol_list)), ws, wsurl, opts, options)


def test_501(ws, wsurl, opts, options):
    if debug:
        print("test 501")
    subprotocol_list = ['MBWS.huawei.com','MBLWS.huawei.com','soap','wamp','v10.stomp','v11.stomp','v12.stomp','ocpp1.2','ocpp1.5','ocpp1.6','ocpp2.0','ocpp2.0.1','rfb','sip','notificationchannel-netapi-rest.openmobilealliance.org','wpcp','amqp','mqtt','jsflow','rwpcp','xmpp','ship','mielecloudconnect','v10.pcp.sap.com','msrp','v1.saltyrtc.org','TLCP-2.0.0.lightstreamer.com','bfcp','sldp.softvelum.com','opcua+uacp','opcua+uajson','v1.swindon-lattice+json','v1.usp','mles-websocket','coap','TLCP-2.1.0.lightstreamer.com','sqlnet.oracle.com','oneM2M.R2.0.json','oneM2M.R2.0.xml','oneM2M.R2.0.cbor','transit','2016.serverpush.dash.mpeg.org','2018.mmt.mpeg.org','clue','webrtc.softvelum.com','cobra.v2.json','drp','hub.bsc.bacnet.org','dc.bsc.bacnet.org','jmap','t140','done','TLCP-2.2.0.lightstreamer.com','collection-update','zap-protocol-v1','chat','superchat','echo-protocol','graphql-ws','graphql-transport-ws','null','webtty','ISYSUB']
    subprotocol_list.reverse()
    return protocol_try_connect(",".join(map(str, subprotocol_list)), ws, wsurl, opts, options)


def run_5xx_tests(ws, wsurl, opts, options):
    results_5xx = {}
    results_5xx['500'] = test_500(ws, wsurl, opts, options)
    results_5xx['501'] = test_501(ws, wsurl, opts, options)
    return results_5xx

################################
# Functions for series 600 tests
# long payload lengths
################################


def max_payloads(verbose, ws, wsurl, opts, options):
    results_6xx = {}
    # Generate long inputs of the following lengths
    long_inputs = [100, 1048576, 1048577, 5095577, 10000000, 16777216, 16777217, 67108863, 67108864, 100000000, 100000001, 104857600, 104857601]
    # Test long inputs
    testcase = 600
    # Always disable tracing here, otherwise log/terminal gets flooded
    websocket.enableTrace(False)
    for length in long_inputs:
        time.sleep(send_delay)
        print("long input length: ", str(length))
        # First try to reconnect if connection is lost
        ws_reconnect(ws, wsurl, opts, options)
        try:
            ws.send("a" * length)
            results_6xx[str(testcase)] = 1
            testcase += 1
        except Exception as e:
            results_6xx[str(testcase)] = 0
            print("long input exception: ", e)
            testcase += 1
    # Re-enable tracing if verbose
    if verbose:
        websocket.enableTrace(True)
    return results_6xx


def run_6xx_tests(verbose, ws, wsurl, opts, options):
    if debug:
        print("test 600")
    results_6xx = max_payloads(verbose, ws, wsurl, opts, options)
    return results_6xx


################################
# Functions for series 700 tests
# hybi draft support
################################

def send_req(req, wsurl, opts):
    # Extract host and port
    host = urlparse(wsurl).hostname
    port = urlparse(wsurl).port or (80 if urlparse(wsurl).scheme == "ws" else 443)

    data = ""

    if urlparse(wsurl).scheme == "wss":
        context = ssl.SSLContext(opts.get('ssl_version', ssl.PROTOCOL_TLS_CLIENT))
        context.check_hostname = opts.get('check_hostname', True)
        context.verify_mode = opts.get('cert_reqs', ssl.CERT_REQUIRED)
        with socket.create_connection((host, port)) as sock:
            sock.settimeout(cntn_timeout)
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.sendall(req)
                data = ssock.recv(4096)
    elif urlparse(wsurl).scheme == "ws":
        ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssock.connect((host, int(port)))
        ssock.send(req)
        data = ssock.recv(4096)
    else:
        raise Exception("ERROR: neither wss or ws protocol scheme detected")

    response = ""

    # Send request and receive response
    if debug:
        print("================REQ1================")
        print(req.decode(errors='ignore'))
    if debug:
        print("++++++++++++++++RES2++++++++++++++++")
        if len(data) > 1:
            print(data.decode(errors='ignore'))
            response = data.decode(errors='ignore')
        else:
            print("")

    if len(response) < 2:
        return 0
    # Parse response
    status_code = response.split(" ")[1]
    response_body = response.split("\n")[-2] + response.split("\n")[-1].rstrip()
    if len(response_body) > 1:
        # TODO: return both HTTP response status code and body, not just body
        return response_body.replace('\r', '')
    else:
        return status_code


def test_700(ws, wsurl, opts, options):
    if debug:
        print("test 700")
    path = urlparse(wsurl).path or "/"
    # Missing version number
    req = (
        b"GET " + path.encode('utf-8') + b" HTTP/1.1\r\n" +
        b"Upgrade: websocket\r\n" +
        b"Host: " + urlparse(wsurl).hostname.encode('utf-8') + b"\r\n" +
        b"Origin: http://" + urlparse(wsurl).hostname.encode('utf-8') + b"\r\n" +
        b"Sec-WebSocket-Version: \r\n" +
        b"Sec-WebSocket-Key: 2O2jInxpACZenZ+b6an9kw==\r\n" +
        b"Connection: Upgrade\r\n" +
        b"\r\n"
    )
    return send_req(req, wsurl, opts)


def test_701(ws, wsurl, opts, options):
    if debug:
        print("test 701")
    path = urlparse(wsurl).path or "/"
    # Bad upgrade value
    req = (
        b"GET " + path.encode('utf-8') + b" HTTP/1.1\r\n" +
        b"Upgrade: websocketa\r\n" +
        b"Host: " + urlparse(wsurl).hostname.encode('utf-8') + b"\r\n" +
        b"Origin: http://" + urlparse(wsurl).hostname.encode('utf-8') + b"\r\n" +
        b"Sec-WebSocket-Version: 13\r\n" +
        b"Sec-WebSocket-Key: 2O2jInxpACZenZ+b6an9kw==\r\n" +
        b"Connection: Upgrade\r\n" +
        b"\r\n"
    )
    return send_req(req, wsurl, opts)


def test_702(ws, wsurl, opts, options):
    if debug:
        print("test 702")
    # hybi-XX connection attempt
    req = (
        b"HTTP/1.1 101 WebSocket Protocol Handshake\r\n" +
        b"Upgrade: websocket\r\n" +
        b"Connection: Upgrade\r\n" +
        b"Sec-WebSocket-Origin: http://" + urlparse(wsurl).hostname.encode('utf-8') + b"\r\n" +
        b"Sec-WebSocket-Location: " + wsurl.encode('utf-8') + b"\r\n" +
        b"\r\n"
    )
    return send_req(req, wsurl, opts)


def test_703(ws, wsurl, opts, options):
    if debug:
        print("test 703")
    path = urlparse(wsurl).path or "/"
    # hybi-XX connection attempt
    req = (
        b"GET " + path.encode('utf-8') + b" HTTP/1.1\r\n" +
        b"Host: example.com\r\n" +
        b"Connection: Upgrade\r\n" +
        b"Sec-WebSocket-Key2: 12998 5 Y3 1  .P00\r\n" +
        b"Sec-WebSocket-Protocol: sample\r\n" +
        b"Upgrade: WebSocket\r\n" +
        b"Sec-WebSocket-Key1: 4 @1  46546xW%0l 1 5\r\n" +
        b"Origin: http://" + urlparse(wsurl).hostname.encode('utf-8') + b"\r\n" +
        b"\r\n"
    )
    return send_req(req, wsurl, opts)


def test_704(ws, wsurl, opts, options):
    if debug:
        print("test 704")
    path = urlparse(wsurl).path or "/"
    # hybi-76 connection attempt
    req = (
        b"GET " + path.encode('utf-8') + b" HTTP/1.1\r\n" +
        b"Upgrade: websocket\r\n" +
        b"Host: " + urlparse(wsurl).hostname.encode('utf-8') + b"\r\n" +
        b"Connection: Upgrade\r\n" +
        b"Origin: http://www.example.com\r\n" +
        b"Sec-WebSocket-Key1: 1   38 wZ3f9 23O0 3l 0r\r\n" +
        b"Sec-WebSocket-Key2: 27   0E 6 2  1665:< ;U 1H\r\n" +
        b"\r\n" +
        b"^n:ds[4U\r\n"
    )
    return send_req(req, wsurl, opts)


def test_705(ws, wsurl, opts, options):
    if debug:
        print("test 705")
    path = urlparse(wsurl).path or "/"
    # hybi-76, no Host header
    req = (
        b"GET " + path.encode('utf-8') + b" HTTP/1.1\r\n" +
        b"Connection: Upgrade\r\n" +
        b"Upgrade: websocket\r\n" +
        b"Origin: http://" + urlparse(wsurl).hostname.encode('utf-8') + b"\r\n" +
        b"Sec-WebSocket-Key1: 1   38 wZ3f9 23O0 3l 0r\r\n" +
        b"Sec-WebSocket-Key2: 27   0E 6 2  1665:< ;U 1H\r\n" +
        b"\r\n"
    )
    return send_req(req, wsurl, opts)


def run_7xx_tests(ws, wsurl, opts, options):
    results_7xx = {}
    results_7xx['700'] = test_700(ws, wsurl, opts, options)
    results_7xx['701'] = test_701(ws, wsurl, opts, options)
    results_7xx['702'] = test_702(ws, wsurl, opts, options)
    results_7xx['703'] = test_703(ws, wsurl, opts, options)
    results_7xx['704'] = test_704(ws, wsurl, opts, options)
    results_7xx['705'] = test_705(ws, wsurl, opts, options)
    return results_7xx


def run_tests(arguments):
    global debug
    # Create empty vars
    wsurl = ""
    options = {}
    opts = {}
    args = arguments

    if args.debug:
        debug = True

    # Set schema prefix
    if args.no_encryption:
        wsurl = "ws://" + args.url
    else:
        wsurl = "wss://" + args.url

    # Set SSL options if certs should be ignored
    if args.nocert:
        opts = {"check_hostname": False, "cert_reqs": ssl.CERT_NONE}

    # Set origin if none is provided
    if args.origin is None:
        options["origin"] = "http://" + urlparse(wsurl).netloc

    # Raise exception if http schema is included in URLs
    if args.url.find("http://") == 0 or args.url.find("https://") == 0:
        raise Exception("URLs should not contain http:// or https:// - \
        please read the README and clean these from the input URLs")

    # Try connecting websocket (may fail)
    try:
        ws = websocket.WebSocket(sslopt=opts)
        ws.connect(wsurl, skip_utf8_validation=True, timeout=cntn_timeout, **options)
    except Exception as e:
        print("Exception while trying first connection attempt: ", e)

    results_1xx = {}
    results_2xx = {}
    results_3xx = {}
    full_fingerprint = {}
    if args.all_tests or args.generate_fingerprint:
        if args.series_100 or args.series_200 or args.series_300 or args.series_400 or args.series_500 or args.series_600 or args.series_700:
            raise Exception("Run EITHER all tests or specific tests, not both!")
        else:
            if debug:
                cprint.info("Running all tests")
            args.series_100 = True
            args.series_200 = True
            args.series_300 = True
            args.series_400 = True
            args.series_500 = True
            args.series_600 = True
            args.series_700 = True
    if args.series_100:
        if debug:
            cprint.info("Running series 100 tests")
        results_1xx = run_1xx_tests(ws, wsurl, opts, options)
        for test, result in results_1xx.items():
            full_fingerprint[test] = result
    if args.series_200:
        if debug:
            cprint.info("Running series 200 tests")
        results_2xx = run_2xx_tests(ws, wsurl, opts, options)
        for test, result in results_2xx.items():
            full_fingerprint[test] = result
    if args.series_300:
        if debug:
            cprint.info("Running series 300 tests")
        results_3xx = run_3xx_tests(ws, wsurl, opts, options)
        for test, result in results_3xx.items():
            full_fingerprint[test] = result
    if args.series_400:
        if debug:
            cprint.info("Running series 400 tests")
        results_4xx = run_4xx_tests(ws, wsurl, opts, options)
        for test, result in results_4xx.items():
            full_fingerprint[test] = result
    if args.series_500:
        if debug:
            cprint.info("Running series 500 tests")
        results_5xx = run_5xx_tests(ws, wsurl, opts, options)
        for test, result in results_5xx.items():
            full_fingerprint[test] = result
    if args.series_600:
        if debug:
            cprint.info("Running series 600 tests")
        results_6xx = run_6xx_tests(arguments.verbose, ws, wsurl, opts, options)
        for test, result in results_6xx.items():
            full_fingerprint[test] = result
    if args.series_700:
        if debug:
            cprint.info("Running series 700 tests")
        results_7xx = run_7xx_tests(ws, wsurl, opts, options)
        for test, result in results_7xx.items():
            full_fingerprint[test] = result

    return full_fingerprint


def resultsEqual(dbValue, testValue):
    if dbValue == testValue:
        return 0
    else:
        return 1


def resultsContain(dbValue, testValue):
    if isinstance(testValue, int):
        if str(testValue).find(str(dbValue)) >= 0:
            return 0
        else:
            # Attached greater weighter because matching
            # strings are more indicative of a match
            return 2
    else:
        if str(testValue).find(str(dbValue)) >= 0:
            return 0
        else:
            # Attached greater weighter because matching
            # strings are more indicative of a match
            return 2


def first_best_match(deltas, servers, max_delta):
    min_delta = min(deltas)
    candidate_servers = []
    for i in range(len(deltas)):
        if deltas[i] == min_delta:
            candidate_servers.append(servers[i])
    percent_match = 100 * float(1 - min_delta / max_delta)
    return_string = ', '.join(candidate_servers) + " -- % match: " + str(percent_match)
    return return_string


def second_best_match(deltas, servers, max_delta):
    min_delta = min(deltas)
    # Delete minimum delta from list, to find 2nd lowest delta
    while min_delta in deltas:
        location = deltas.index(min_delta)
        del deltas[location]
        del servers[location]
    # Now find the new minimum
    # First handle case where all servers are equally likely (AKA unknown)
    if len(deltas) == 0:
        return "All servers equally likely (unknown fingerprint)"
    else:
        new_min_delta = min(deltas)
        candidate_servers = []
        for i in range(len(deltas)):
            if deltas[i] == new_min_delta:
                candidate_servers.append(servers[i])
        percent_match = 100 * float(1 - new_min_delta / max_delta)
        return_string = ', '.join(candidate_servers) + " -- % match: " + str(percent_match)
        return return_string


def identify_fingerprint(unknown_fingerprint):
    fingerprintDB = [
        # URL #1: NodeJS ws (port 8081 of WebSockets-Playground)
        {'100': 1, '101': 1, '102': 1, '103': 1, '104': 1, '105': 1,
         '200': 1, '201': 1, '202': 1, '203': 1, '204': 1, '205': 1, '206': 1,
         '300': 0, '301': 1, '302': 0, '303': 0, '304': 0, '305': 1, '306': 0, '307': 0, '308': 0, '309': 0, '310': 0,
         '400': 0, '401': 0, '402': 0, '403': 0, '404': 0, '405': 0,
         '500': 'MBWS.huawei.com', '501': 'ISYSUB',
         '600': 1, '601': 1, '602': 1, '603': 1, '604': 1, '605': 1, '606': 1, '607': 1, '608': 1, '609': 1, '610': 1, '611': 1, '612': 0,
         '700': 'Bad Request', '701': 'Bad Request', '702': '400', '703': 'Bad Request', '704': 'Bad Request', '705': 'Bad Request'},
        # URL #2: faye (port 7000 of WebSockets-Playground)
        {'100': 1, '101': 1, '102': 0, '103': 0, '104': 'Received unexpected continuation frame', '105': 1,
         '200': 'One or more reserved bits are on: reserved1 = 0, reserved2 = 0, reserved3 = 1', '201': 'One or more reserved bits are on: reserved1 = 0, reserved2 = 0, reserved3 = 1', '202': 'One or more reserved bits are on: reserved1 = 0, reserved2 = 0, reserved3 = 1', '203': 'One or more reserved bits are on: reserved1 = 0, reserved2 = 0, reserved3 = 1', '204': 'One or more reserved bits are on: reserved1 = 0, reserved2 = 0, reserved3 = 1', '205': 'One or more reserved bits are on: reserved1 = 0, reserved2 = 0, reserved3 = 1', '206': 'One or more reserved bits are on: reserved1 = 0, reserved2 = 0, reserved3 = 1',
         '300': 1, '301': 1, '302': 1, '303': 1, '304': 1, '305': 1, '306': 0, '307': 1, '308': 1, '309': 0, '310': 0,
         '400': 0, '401': 0, '402': 0, '403': 0, '404': 0, '405': 0,
         '500': 0, '501': 0,
         '600': 1, '601': 1, '602': 1, '603': 1, '604': 1, '605': 1, '606': 1, '607': 1, '608': 0, '609': 0, '610': 0, '611': 0, '612': 0,
         '700': 'Unsupported WebSocket version', '701': 'Not a WebSocket request', '702': '400', '703': '101', '704': 'yTFHc]O', '705': '101'},
        # URL #3: Gorilla (port 8084 of WebSockets-Playground)
        {'100': 1, '101': 1, '102': 0, '103': 0, '104': 'continuation after final message frame', '105': 1,
         '200': 'unexpected reserved bits 0x10', '201': 'unexpected reserved bits 0x10', '202': 'unexpected reserved bits 0x10', '203': 'unexpected reserved bits 0x10', '204': 'unexpected reserved bits 0x10', '205': 'unexpected reserved bits 0x10', '206': 'unexpected reserved bits 0x10',
         '300': 0, '301': 0, '302': 0, '303': 1, '304': 0, '305': 0, '306': 0, '307': 0, '308': 0, '309': 0, '310': 0,
         '400': 0, '401': 0, '402': 0, '403': 0, '404': 0, '405': 0,
         '500': 0, '501': 0,
         '600': 1, '601': 1, '602': 1, '603': 1, '604': 1, '605': 1, '606': 1, '607': 1, '608': 1, '609': 1, '610': 1, '611': 1, '612': 1,
         '700': 'Bad Request', '701': 'Bad Request', '702': '400 Bad Request', '703': 'Bad Request', '704': 'Bad Request', '705': '400 Bad Request: missing required Host header'},
        # URL #4: uWebSockets (port 9001 of WebSockets-Playground)
        {'100': 1, '101': 1, '102': 0, '103': 0, '104': 0, '105': 1,
         '200': 0, '201': 0, '202': 0, '203': 0, '204': 0, '205': 0, '206': 0,
         '300': 1, '301': 1, '302': 1, '303': 1, '304': 1, '305': 1, '306': 0, '307': 1, '308': 1, '309': 1, '310': 0,
         '400': 'permessage-deflate; client_no_context_takeover; server_no_context_takeover', '401': 'permessage-deflate; client_no_context_takeover; server_no_context_takeover', '402': 'permessage-deflate; client_no_context_takeover; server_no_context_takeover', '403': 'permessage-deflate; client_no_context_takeover; server_no_context_takeover', '404': 'permessage-deflate; client_no_context_takeover; server_no_context_takeover', '405': 'permessage-deflate; client_no_context_takeover; server_no_context_takeover',
         '500': 'MBWS.huawei.com', '501': 'ISYSUB',
         '600': 1, '601': 1, '602': 1, '603': 1, '604': 1, '605': 1, '606': 0, '607': 0, '608': 0, '609': 0, '610': 0, '611': 0, '612': 0,
         '700': '101', '701': '101', '702': 0, '703': 0, '704': 0, '705': 0},
        # URL #5: Java Spring boot (port 8080 of WebSockets-Playground)
        {'100': 0, '101': 0, '102': 0, '103': 0, '104': 'A WebSocket frame was sent with an unrecognised opCode of [0]', '105': 'The client sent a close frame with a single byte payload which is not valid',
         '200': 'The client frame set the reserved bits to [1] for a message with opCode [2] which was not supported by this endpoint', '201': 'The client frame set the reserved bits to [1] for a message with opCode [2] which was not supported by this endpoint', '202': 'The client frame set the reserved bits to [1] for a message with opCode [2] which was not supported by this endpoint', '203': 'The client frame set the reserved bits to [1] for a message with opCode [2] which was not supported by this endpoint', '204': 'The client frame set the reserved bits to [1] for a message with opCode [2] which was not supported by this endpoint', '205': 'The client frame set the reserved bits to [1] for a message with opCode [2] which was not supported by this endpoint', '206': 'The client frame set the reserved bits to [1] for a message with opCode [2] which was not supported by this endpoint',
         '300': 0, '301': 0, '302': 0, '303': 0, '304': 0, '305': 0, '306': 1, '307': 0, '308': 0, '309': 0, '310': 0,
         '400': 'permessage-deflate', '401': 'permessage-deflate', '402': 'permessage-deflate', '403': 'permessage-deflate', '404': 'permessage-deflate', '405': 'permessage-deflate',
         '500': 0, '501': 0,
         '600': 0, '601': 0, '602': 0, '603': 0, '604': 0, '605': 0, '606': 0, '607': 0, '608': 0, '609': 0, '610': 0, '611': 0, '612': 0,
         '700': '426', '701': 'Can "Upgrade" only to "WebSocket".', '702': 'Bad Request', '703': '403', '704': 'Bad Request', '705': 'Bad Request'},
        # URL #6: Python websockets (port 8765 of WebSockets-Playground)
        {'100': 1, '101': 1, '102': 0, '103': 0, '104': 1, '105': 1,
         '200': 1, '201': 1, '202': 1, '203': 1, '204': 1, '205': 1, '206': 1,
         '300': 0, '301': 0, '302': 0, '303': 0, '304': 0, '305': 0, '306': 0, '307': 0, '308': 0, '309': 3, '310': 0,
         '400': -1, '401': -1, '402': -1, '403': -1, '404': -1, '405': -1,
         '500': 0, '501': 0,
         '600': 1, '601': 1, '602': 1, '603': 0, '604': 0, '605': 0, '606': 0, '607': 0, '608': 0, '609': 0, '610': 0, '611': 0, '612': 0,
         '700': 'Failed to open a WebSocket connection: empty Sec-WebSocket-Version header.', '701': 'You cannot access a WebSocket server directly with a browser. You need a WebSocket client.', '702': 'Failed to open a WebSocket connection: did not receive a valid HTTP request.', '703': 'Failed to open a WebSocket connection: missing Sec-WebSocket-Key header.', '704': 'Failed to open a WebSocket connection: missing Sec-WebSocket-Key header.', '705': 'Failed to open a WebSocket connection: missing Sec-WebSocket-Key header.'},
        # URL #7: Ratchet (port 8085 of WebSockets-Playground)
        {'100': 0, '101': 0, '102': 0, '103': 0, '104': 'Ratchet detected', '105': 'Ratchet detected',
         '200': 'Ratchet detected an invalid reserve code', '201': 'Ratchet detected an invalid reserve code', '202': 'Ratchet detected an invalid reserve code', '203': 'Ratchet detected an invalid reserve code', '204': 'Ratchet detected an invalid reserve code', '205': 'Ratchet detected an invalid reserve code', '206': 'Ratchet detected an invalid reserve code',
         '300': 0, '301': 0, '302': 1, '303': 1, '304': 1, '305': 1, '306': 0, '307': 1, '308': 1, '309': 2, '310': 0,
         '400': 0, '401': 0, '402': 0, '403': 0, '404': 0, '405': 0,
         '500': -1, '501': -1,
         '600': 1, '601': 1, '602': 1, '603': 1, '604': 1, '605': 1, '606': 0, '607': 0, '608': 0, '609': 0, '610': 0, '611': 0, '612': 0,
         '700': 0, '701': 0, '702': 0, '703': 0, '704': 0, '705': 0},
        # URL #8: Tornado (port 3000 of WebSockets-Playground)
        {'100': 0, '101': 0, '102': 0, '103': 0, '104': 0, '105': 1,
         '200': 0, '201': 0, '202': 0, '203': 0, '204': 0, '205': 0, '206': 0,
         '300': 1, '301': 1, '302': 0, '303': 0, '304': 0, '305': 1, '306': 1, '307': 0, '308': 0, '309': 0, '310': 0,
         '400': 0, '401': 0, '402': 0, '403': 0, '404': 0, '405': 0,
         '500': 0, '501': 0,
         '600': 1, '601': 1, '602': 1, '603': 1, '604': 1, '605': 0, '606': 0, '607': 0, '608': 0, '609': 0, '610': 0, '611': 0, '612': 0,
         '700': '426', '701': 'Can "Upgrade" only to "WebSocket"', '702': '400', '703': '426', '704': '426', '705': '426'}
    ]
    dbServers = ["NodeJS ws", "Faye", "Gorilla", "uWebSockets", "Java Spring boot", "Python websockets", "Ratchet", "Python Tornado"]
    if len(fingerprintDB) != len(dbServers):
        cprint.err("ERROR - fingerprint database list length doesn't match server name list length")
    fprintDeltas = []

    print("=======================================================")
    cprint.info("Identifying...")
    print("=======================================================")
    equalityCases = ['100', '101', '102', '103',
                     '300', '301', '302', '303', '304', '305', '306', '307', '308', '309', '310',
                     '400', '401', '402', '403', '404', '405',
                     '500', '501',
                     '600', '601', '602', '603', '604', '605', '606', '607', '608', '609', '609', '610', '611', '612']
    containCases = ['104', '105',
                    '200', '201', '202', '203', '204', '205', '206',
                    '700', '701', '702', '703', '704', '705']
    for fprint in fingerprintDB:
        delta = 0
        for testcase in equalityCases:
            # Skip check if test case not in either database of test results
            if testcase in unknown_fingerprint.keys() and testcase in fprint.keys():
                delta += resultsEqual(fprint[testcase], unknown_fingerprint[testcase])
        for testcase in containCases:
            # Skip check if test case not in either database of test results
            if testcase in unknown_fingerprint.keys() and testcase in fprint.keys():
                delta += resultsContain(fprint[testcase], unknown_fingerprint[testcase])
        fprintDeltas.append(delta)
    max_delta = 0
    for key in unknown_fingerprint:
        if key in equalityCases:
            max_delta += 1  # Account for weighting in resultsEqual function
        elif key in containCases:
            max_delta += 2  # Account for weighting in resultsContain function
    candidate_index = fprintDeltas.index(min(fprintDeltas))
    print("List of deltas between detected fingerprint and those in database")
    print(fprintDeltas)
    print("=======================================================")
    cprint.info(">>>Most likely server: " + first_best_match(fprintDeltas, dbServers, max_delta))
    cprint.info(">>>Second most likely server: " + second_best_match(fprintDeltas, dbServers, max_delta))
    print("=======================================================")
    print("Most likely server's fingerprint: ")
    print(fingerprintDB[candidate_index])
    print("=======================================================")
    print("Tested server's fingerprint: ")
    print(unknown_fingerprint)


def main():
    global debug
    final_fingerprint = []
    # Parse input arguments
    args = parse_args()

    # Set verbosity
    if args.verbose:
        debug = True
        websocket.enableTrace(True)
    # Raise exception if no URL or file is provided
    if args.url is None and args.file is None:
        raise Exception("ERROR: Either a URL or file containing URLs must be provided")

    # Raise exception if no test-related args are set
    if args.generate_fingerprint is False and args.all_tests is False and \
        args.series_100 is False and args.series_200 is False and args.series_300 is False and \
        args.series_400 is False and args.series_500 is False and args.series_600 is False and \
        args.series_700 is False:
        raise Exception("ERROR: Set flags to test a server or generate a fingerprint for a server")

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
            final_fingerprint = run_tests(args)
            # Print fingerprint if debugging or if generating fingerprint
            if debug or args.generate_fingerprint:
                print("=======================================================")
                print("=======================================================")
                print("Fingerprint of URL " + args.url)
                print(final_fingerprint)
            # Identify fingerprint, unless generating one
            if args.generate_fingerprint is False:
                identify_fingerprint(final_fingerprint)
    ############################################
    # Start here if a single URL argument was provided
    ############################################
    else:
        # Run tests
        final_fingerprint = run_tests(args)
        # Print fingerprint if debugging or if generating fingerprint
        if debug or args.generate_fingerprint:
            print("Fingerprint of URL " + args.url)
            print(final_fingerprint)
        # Identify fingerprint, unless generating one
        if args.generate_fingerprint is False:
            identify_fingerprint(final_fingerprint)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
