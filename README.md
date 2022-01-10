# STEWS: Security Testing and Enumeration of WebSockets

![STEWS cauldron image](stews-image.jpg)

STEWS is a tool suite for security testing of WebSockets

This research was first presented at
[OWASP Global AppSec US 2021](https://www.youtube.com/watch?v=bMFP71UAbPo)

## Features
STEWS provides the ability to:
- **Discover**: find WebSockets endpoints on the web by testing a list of domains
- **Fingerprint**: determine what WebSockets server is running on the endpoint
- **Vulnerability Detection**: test whether the WebSockets server is vulnerable to a known WebSockets vulnerability

The included whitepaper in this repository provides further details of
the research undertaken.
The included slide deck was presented at OWASP AppSec US 2021.

Complementary respositories created as part of this research include:
- The [Awesome WebSocket Security repository](https://github.com/PalindromeLabs/awesome-websocket-security), which compiles WebSockets security information
for future researchers
- The [WebSockets-Playground repository](https://github.com/PalindromeLabs/WebSockets-Playground), which is a script to easily jump start
multiple local WebSocket servers in parallel

## Installation & Usage

Each portion of STEWS (discovery, fingerprinting, vulnerability detection)
has separate instructions. Please see the README in each respective folder.

### WebSocket Discovery

See the [discovery README](discovery/README.md)

### WebSocket Fingerprinting

See the [fingerprinting README](fingerprint/README.md)

### WebSocket Vulnerability Detection

See the [vulnerability detection README](vuln-detect/README.md)

## Why this tool?

WebSocket servers have been largely ignored in security circles.
This is partially due to three hurdles that have not been clearly
addressed for WebSocket endpoints:

1. Discovery
2. Enumeration/fingerprinting
3. Vulnerability detecting

STEWS attempts to address these three points. A custom tool was required
because there is a distinct lack of support for manually configured WebSocket
testing in current security testing tools:

1. There is a general lack of supported and scriptable WebSocket security testing tools
(for example, NCC's unsupported [wssip tool](https://github.com/nccgroup/wssip/issues),
[nuclei's lack of WebSocket support](https://github.com/projectdiscovery/nuclei/issues/539),
and [nmap's lack of WebSocket support](https://seclists.org/nmap-dev/2015/q1/134))
2. Burp Suite lacks support for WebSocket extensions (for example, see [this PortSwigger forum thread](https://forum.portswigger.net/thread/websockets-api-support-c8e1660b9f0ab) and [this one](https://forum.portswigger.net/thread/websocket-api-07e77f9ee3dd58552eb770)).
3. There is a lack of deeper WebSocket-specific security research (the [Awesome WebSocket Security repository](https://github.com/PalindromeLabs/awesome-websocket-security) lists published WebSockets security research)
4. The proliferation of WebSockets around the modern web (as seen in the results
of the STEWS discovery tool)
