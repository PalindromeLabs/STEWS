# STEWS Discovery Tool

The STEWS (Security Tool for Enumerating WebSockets) discovery tool uses
a custom fork of ZGrab2 to test URLs for WebSocket support by sending the
first part of a WebSocket connection handshake. If the server responds to this
WebSocket connection request with a HTTP 101 "Switching Protocols" response,
it can be assumed that the server supports WebSockets.
The approach used for WebSocket endpoint discovery is a brute-force approach
that relies on a wordlist. This is because WebSockets may only be accessible
at a specific path of a server. By sending out large numbers of these WebSocket
handshake requests and filtering for servers that respond with
a 101 status code, many WebSocket endpoints can be discovered.
However, there are some weaknesses to this approach:
- Specific URL paths are tested, which means that a WebSocket endpoint not
at this location will not be detected.
- ZGrab2 is a work in progress, with some key PRs for improved HTTP support
merged in the last year or two
- ZGrab2 was not originally designed to operate at the HTTP layer,
but at the TCP/IP layer. Therefore, ZGrab2 doesn't solve high throughput
DNS lookups and this can be a problem point depending on your configuration.
See the following DNS tip for the current recommended approach.

## DNS tips

If you have used a common web fuzzer or URL brute force tool such as
[gobuster](https://github.com/OJ/gobuster) or [ffuf](https://github.com/ffuf/ffuf),
you have likely used this tool against a single domain. Because the STEWS
discovery process is testing many different domains, a large number of DNS
requests will occur. The DNS lookup process can take just as much time, if
not more, than sending the actual WebSockets request.
If you are using your ISP's default DNS server, you will likely
reach the lookup rate limit and start encountering DNS errors that
can cause missed WebSocket endpoints.

The approach used for testing on a vanilla Ubuntu system that is relying on the
/etc/resolv.conf file for DNS server is to add several well-known public DNS
servers, such as Google (8.8.8.8 and 8.8.4.4), Quad9 (9.9.9.9), and
Cloudflare (1.1.1.1 and 1.0.0.1) to the /etc/resolve.conf file. When your system
is performing the DNS lookups and does not get a response
from the first DNS nameserver, it will use other DNS
servers in the /etc/resolv.conf, which can help balance the DNS
request load in case the rate limit has been hit on other nameservers
in the /etc/resolv.conf file.

There are optimizations that can speed up discovery beyond the approach described
above. For example, zgrab2 accepts input files that contain the IP of the domain,
in the format `IP,domain`, to allow zgrab2 to skip the DNS lookup step. This
approach saves time if many URL paths are being tested
(1 DNS lookup per domain rather than a DNS lookup per domain
for each URL path tested).

If you aren't discovering any WebSockets endpoints and suspect DNS lookups may
be the issue, you can use Wireshark or tcpdump to troubleshoot the issue.

## Domain list tips

There are many ways to get a long list of domains to test for WebSockets.

1. If you want to manually find endpoints to discover new URL paths where
WebSockets may exist beyond what is listed in the
[sample discovery results table](#sample-discovery-results),
there aren't many known shortcuts beyond manual browsing. Finding
repositories on GitHub that contain many WebSockets endpoints
(such as this [cryptofeed repo](https://github.com/bmoscon/cryptofeed)).
2. If you are focused on testing a specific domain or set of domains,
you can use a list of the domains and subdomains in scope.
3. If you are scanning the web, you can either search
on your favorite search engine for "top million domains"
or "top 100 million domains". Lastly, for a more comprehensive
list of domains, you can request access to the same source that
top level DNS servers use, zone files. You can
[submit a request to ICANN](https://czds.icann.org/home) for these zone files.
As a warning, the .com zone file is a 21+ GB text file and the .org zone file
is 1.5+ GB. Additionally, the zone files contain many domains that resolve to
0.0.0.0, internal IPs, etc. that could be cleaned or minified before using.

## Usage and dependencies

The `STEWS-discovery.sh` script is a bash script tested on Linux.
The only dependencies are [jq](https://github.com/stedolan/jq)
and a zgrab2 binary from the custom
[Palindrome Technologies zgrab2 fork](https://github.com/PalindromeLabs/zgrab2)
(a working binary can be downloaded from
[here](https://github.com/PalindromeLabs/zgrab2/releases/download/v0.1.7/zgrab2)).
This zgrab2 fork makes the following changes (as of Nov 2021):
- The `DynamicOrigin` flag is added to set the "Origin" header to the
target domain without path (in case Origin is checked for CSWSH mitigation)
- To simplify the WebSockets handshake HTTP request, the UserAgent header,
the Accept-Encoding header, and the Accept header are all removed,
the latter using a new `RemoveAcceptHeader` flag
- The `Endpoint` flag is removed because the endpoint path is included in the
URL list provided as input

The script uses the `known-endpoints.txt` by default
(these known WebSockets servers are part of bug bounty programs),
but any text file of domains can be provided as input.

The `STEWS-discover.sh` script can be modified to view additional information
about each server. For example, adding `.data.http.result.response.headers` to
the values provided to `jq` will output the headers from each server.

## Sample discovery results

From a sample size of ~3 million domains tested in Nov 2021,
the following table illustrates the number of servers
discovered that supported WebSockets for each URL pattern.
The xxx characters imply a variety of TLDs were tested.

<!-- markdown-link-check-disable -->
| URL                       |  WebSocket servers found   |
| :------------------------ | :------------------------  |
| domain.xxx                |            2281            |
| domain.xxx/ws             |            1991            |
| domain.xxx/ws/v1          |            1605            |
| domain.xxx/ws/v2          |            1606            |
| domain.xxx/socket.io/?EIO=3&transport=websocket | 1389 |
| domain.xxx/stream         |            448             |
| domain.xxx/feed           |            452             |
| www.domain.xxx            |            1582            |
| ws.domain.xxx             |            891             |
| stream.domain.xxx         |            574             |
| **Total**                 |         **12819**          |
<!-- markdown-link-check-enable -->

## Areas for future work

1. Creating a more extensive list of common WebSocket URL paths and ports
other than 443 to test
2. Deeper analysis of the public WebSockets endpoints discovered
3. Using a web crawler with JavaScript support to more extensively test for
WebSockets in a single domain. This is a different approach than using STEWS-discovery.sh
and would focus more on depth-first rather than breadth-first. This would be
useful when security testing a single domain, and the data collected from such a
tool could improve the word list used for the zgrab2 brute force discovery method.
