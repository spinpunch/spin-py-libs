#!/usr/bin/env python

# Copyright (c) 2015 Battlehouse Inc. All rights reserved.
# Use of this source code is governed by an MIT-style license that can be
# found in the LICENSE file.

# HTTP utilities

from six import PY2
import time, re
from ipaddress import IPv6Address, IPv6Network

# create RFC2822 timestamp
def format_http_time(stamp):
    return time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(stamp))

from email.utils import mktime_tz, parsedate_tz

# parse RFC2822 timestamp, inverse of format_http_time()
def parse_http_time(http_time):
    return long(mktime_tz(parsedate_tz(http_time)))

import base64

# wrap/unwrap Unicode text strings for safe transmission across the AJAX connection
# mirrors gameclient/clientcode/SPHTTP.js

def unwrap_string(input):
    return unicode(base64.b64decode(str(input)).decode('utf-8'))

def wrap_string(input):
    return base64.b64encode(input.encode('utf-8'))

# below functions are specific to Twisted

from twisted import __version__ as twisted_version
twisted_major_version = int(twisted_version.split('.')[0])
from twisted.web.server import NOT_DONE_YET
from twisted.web.http import INTERNAL_SERVER_ERROR
from twisted.python.failure import Failure

# set cross-site allow headers on Twisted HTTP requests
def _set_access_control_headers(request, origin, max_age):
    if origin:
        request.setHeader('Access-Control-Allow-Origin', origin)
    request.setHeader('Access-Control-Allow-Credentials', 'true')
    request.setHeader('Access-Control-Allow-Methods', 'POST, GET, HEAD, OPTIONS')
    request.setHeader('Access-Control-Allow-Headers', 'X-Requested-With')
    if max_age >= 0:
        request.setHeader('Access-Control-Max-Age', str(max_age))

# get a raw HTTP header from Twisted request object
def get_twisted_header(request, x):
    temp = request.requestHeaders.getRawHeaders(x)
    if temp and len(temp) > 0:
        return str(temp[0])
    else:
        return ''
def set_twisted_header(request, x, val):
    request.requestHeaders.setRawHeaders(x, [val])

def set_access_control_headers(request):
    if request.requestHeaders.hasHeader('origin'):
        origin = get_twisted_header(request, 'origin')
    elif 'spin_origin' in request.args:
        origin = request.args['spin_origin'][-1]
    else:
        origin = '*'
    _set_access_control_headers(request, origin, 7*24*60*60)

def set_access_control_headers_for_cdn(request, max_age):
    # ensure that we ONLY attach a non-wildcard origin if it's in the query string
    if 'spin_origin' in request.args:
        origin = request.args['spin_origin'][-1]
    else:
        origin = '*'
    _set_access_control_headers(request, origin, max_age)

def set_service_unavailable(request):
    request.setResponseCode(503) # 503 Service Unavailable
    request.setHeader('Retry-After', '600') # suggest retrying in 10 minutes

service_unavailable_response_body = '503 Service Unavailable, please try again later\n'

def set_accepted(request):
    request.setResponseCode(202) # 202 Accepted
    # The request has been accepted for processing, but the processing has not been completed. The request might or might not be eventually acted upon, and may be disallowed when processing occurs.
    # request.setHeader('Connection', 'close')

accepted_response_body = '{"result": "ok", "status": 202}\n'

def set_twisted_cookie(request, cookie_name, value, expire_time,
                       domain = None, path = None, secure = None, httpOnly = False):
    if twisted_major_version >= 16:
        request.addCookie(cookie_name, value, expires = format_http_time(expire_time),
                          domain = domain, path = path, secure = secure, httpOnly = httpOnly)
    else:
        # Twisted before 16.3.2 and before 15.5.0 are missing httpOnly param to addCookie()
        request.addCookie(cookie_name, value, expires = format_http_time(expire_time),
                          domain = domain, path = path, secure = secure)

    # necessary for IE7+ to accept iframed cookies
    request.setHeader('P3P', 'CP="CAO DSP CURa ADMa DEVa TAIa PSAa PSDa IVAi IVDi CONi OUR UNRi OTRi BUS IND PHY ONL UNI COM NAV INT DEM CNT STA PRE GOV LOC"')

def clear_twisted_cookie(request, cookie_name,
                       domain = None, path = None, secure = None, httpOnly = False):
    set_twisted_cookie(request, cookie_name, 'deleted', 0, domain = domain, path = path, secure = secure, httpOnly = httpOnly)

# get info about an HTTP(S) request, "seeing through" reverse proxies back to the client
# NOTE! YOU MUST SANITIZE (DELETE HEADERS FROM) REQUESTS ACCEPTED DIRECTLY FROM CLIENTS TO AVOID SPOOFING!

# normalize IP input to IPv6 address
def ip_normalize(ip):
    if '.' not in ip: return ip
    ip_chunks = ip.split('.')
    normalized_ip = '2002:B0B1:B2B3::ffff:B0B1:B2B3'
    normalized_ip = '2002:B0B1:B2B3::'
    for i, ip_chunk in enumerate(ip_chunks):
        hexified = str(hex(int(ip_chunk))).replace('0x','')
        if len(hexified) == 1: hexified = '0' + hexified
        normalized_ip = normalized_ip.replace('B%d' % i, hexified)
    return normalized_ip

def is_private_ip(ip):
    if 'unknown' in ip: return True
    ip = int(IPv6Address(ip_normalize(ip)))
    cidrs = ['::/128','::1/128','::ffff:0:0/96','::/96', '100::/64', '2001:10::/28', '2001:db8::/32', 'fc00::/7', 'fe80::/10',
             'fec0::/10', 'ff00::/8', '2002::/24', '2002:a00::/24', '2002:6440::/26', '2002:7f00::/24', '2002:a9fe::/32', '2002:ac10::/28', '2002:c000::/40',
             '2002:c000:200::/40', '2002:c0a8::/32', '2002:c612::/31', '2002:c633:6400::/40', '2002:cb00:7100::/40', '2002:e000::/20',
             '2002:f000::/20', '2002:ffff:ffff::/48', '2001::/40', '2001:0:a00::/40', '2001:0:7f00::/40', '2001:0:a9fe::/48', '2001:0:ac10::/44',
             '2001:0:c000::/56', '2001:0:c000:200::/56', '2001:0:c0a8::/48', '2001:0:c612::/47', '2001:0:c633:6400::/56', '2001:0:cb00:7100::/56',
             '2001:0:e000::/36', '2001:0:f000::/36', '2001:0:ffff:ffff::/64']
    # there are only 40 entries, so no need to do a more efficient search than low to high
    for cidr in cidrs:
        net = IPv6Network(cidr)
        if ip >= int(net[0]) and ip <= int(net[-1]):
            return True
    return False

def get_twisted_raw_ip(request):
   # return the raw IP address of the neighbor connected to us
   if hasattr(request, 'getClientAddress'):
       return request.getClientAddress().host # Twisted v18+
   else:
       return request.getClientIP() # old versions of Twisted

def get_twisted_client_ip(request, proxy_secret = None, trust_x_forwarded = True):
    if proxy_secret:
        forw = get_twisted_header(request, 'spin-orig-ip')
        if forw:
            return forw

    cf_con = get_twisted_header(request, 'CF-Connecting-IP')
    if cf_con:
        return cf_con

    # Incapsula is not used anymore
#    incap = get_twisted_header(request, 'incap-client-ip')
#    if incap:
#        return incap

    # the raw IP address of the neighbor connected to us
    raw_ip = get_twisted_raw_ip(request)

    forw_list = request.requestHeaders.getRawHeaders('X-Forwarded-For')
    if forw_list and len(forw_list) > 0:
        forw = ','.join(map(str, forw_list))
        if forw:
            if trust_x_forwarded or is_private_ip(raw_ip):
                # return leftmost non-private address
                for ip in forw.split(','):
                    ip = ip.strip()
                    if is_private_ip(ip):
                        continue # skip private IPs
                    else:
                        return ip

                # ... or fall back to raw_ip below

            else:
                # can't trust X-Forwarded-For because it came out of a public IP
                # fall back to the native request IP
                if is_private_ip(raw_ip):
                    raise Exception('X-Forwarded-For a private address: %r' % forw)
                else:
                    return raw_ip

    return raw_ip

ipv6_re = re.compile(r'([0-9a-fA-F]{4}):([0-9a-fA-F]{4}):([0-9a-fA-F]{4}):([0-9a-fA-F]{4}):([0-9a-fA-F]{4}):([0-9a-fA-F]{4}):([0-9a-fA-F]{4}):([0-9a-fA-F]{4})')

def ip_matching_key(ip):
    """ Return the value to compare against to detect if clients are 'alts' of each other.
    For IPv4, it's the raw address. But for IPv6, it's the /64 part, since it seems like
    multiple devices on a home network often have different IPv6 addresses within the /64. """
    if len(ip) > 16:
        match = ipv6_re.match(ip)
        if match:
            return ':'.join(match.groups()[0:4]) + '::/64'
    return ip

def twisted_request_is_ssl(request, proxy_secret = None):
    if proxy_secret:
        orig_protocol = get_twisted_header(request, 'spin-orig-protocol')
        if orig_protocol:
            return orig_protocol == 'https://'

    orig_protocol = get_twisted_header(request, 'X-Forwarded-Proto')
    if orig_protocol:
        return orig_protocol.startswith('https')

    return request.isSecure()

# this is the final Deferred callback that finishes asynchronous HTTP request handling
# note that "body" is inserted by Twisted as the return value of the callback chain BEFORE other args.

def complete_deferred_request(body, request, http_status = None):
    if body == NOT_DONE_YET:
        return body

    if PY2:
        if type(body) not in (str, unicode, bytes):
            raise Exception('unexpected body type %r: %r' % (type(body), body))
    else:
        if type(body) is not bytes:
            raise Exception('unexpected body type %r: %r' % (type(body), body))

    if hasattr(request, '_disconnected') and request._disconnected: return
    if http_status:
        request.setResponseCode(http_status)
    request.write(body)
    request.finish()

# wrapper for complete_deferred_request() that handles Failure results so you can put it
# at the end of a Deferred chain and it will do the right thing for successes and errors.
def complete_deferred_request_safe(body, request, http_status = None, full_traceback = False):
    if isinstance(body, Failure):
        request.setHeader('Content-Type', 'text/plain')
        request.setResponseCode(INTERNAL_SERVER_ERROR)
        if full_traceback: # dangerous - includes sensitive info in public error message
            body = '{"error": "%s"}\n' % (repr(repr(body) + '\n' + body.getTraceback())[1:-1]) # convert enclosing ' to "
        else:
            body = '{"error": "%s"}\n' % repr(body)
    complete_deferred_request(body, request, http_status = http_status)
