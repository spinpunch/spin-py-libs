#!/usr/bin/env python

# Copyright (c) 2022 Battlehouse Inc. All rights reserved.
# Use of this source code is governed by an MIT-style license that can be
# found in the LICENSE file.

import base64
import hmac
import hashlib
from six import PY3
import SpinP3
sane_bytes = SpinP3.sane_bytes
sane_str = SpinP3.sane_str

if PY3:
    basestring = str
    unicode = str


def sign_session(user_id, country, session_id, session_time, server_name, auth_user, auth_token, extra_data, secret):
    '''
    create HMAC signature of proxyserver-generated session parameters so
    that gameserver can verify that the params are valid when they come
    back from the client.
    '''
    SALT = '3RqMRLWY9ypDrZt6gNJtukmgWuaqeuzR'
    tosign = str(user_id) + ':' + str(country) + ':' + str(session_id) + ':' + str(session_time) + ':' + str(server_name) + ':' + auth_user + ':' + auth_token + ':' + extra_data + ':' + SALT
    secret = sane_bytes(sane_str(secret))
    tosign = sane_bytes(sane_str(tosign))
    return sane_str(base64.urlsafe_b64encode(hmac.new(secret, msg=tosign, digestmod=hashlib.sha256).digest()))


def sign_proxy_headers(protocol, host, port, uri, ip, referer, secret):
    SALT = sane_str('mzOT9MR8Gs7hWr6FpoSYLXVcCiiqNg9E')
    ip = sane_str(ip.replace(':', '.'))  # handle IPv6 addresses
    tosign = str(protocol) + ':' + str(host) + ':' + str(port) + ':' + str(uri) + ':' + str(ip) + ':' + str(referer) + ':' + SALT
    tosign = sane_bytes(sane_str(tosign))
    secret = sane_bytes(sane_str(secret))
    return sane_str(base64.urlsafe_b64encode(hmac.new(secret, msg=tosign, digestmod=hashlib.sha256).digest()))


class AnonID (object):
    '''
    Mostly-secure tokens for carrying over login information (URL
    parameters etc) between separate index hits in proxyserver.

    To be truly secure, this needs to incorporate some element of the
    frame platform's login token into the "tosign" bit.
    '''
    @classmethod
    def create(cls, expire_time, ip_addr, frame_platform, secret, salt):
        ip_addr = sane_str(ip_addr.replace(':', '.'))  # handle IPv6 addresses
        tosign = sane_bytes(':'.join([sane_str(expire_time), ip_addr, frame_platform, salt]))
        secret = sane_bytes(sane_str(secret))
        mid = sane_bytes('|')
        return sane_str(base64.urlsafe_b64encode(hmac.new(secret, msg=tosign, digestmod=hashlib.sha256).digest()) + mid + tosign)

    @classmethod
    def verify(cls, input, time_now, ip_addr, frame_platform, secret):
        input = sane_bytes(input)
        mid = sane_bytes('|')
        ip_addr = sane_bytes(ip_addr)
        frame_platform = sane_bytes(frame_platform)
        secret = sane_bytes(sane_str(secret))
        if (not input) or (mid not in input) or len(input) < 10:
            return False
        sig, tosign = input.split(mid)
        fields = tosign.split(sane_bytes(':'))
        if len(fields) != 4:
            return False
        s_expire_time, s_ip_addr, s_frame_platform, s_salt = fields
        # handle IPv6 addresses
        if sane_bytes(':') in ip_addr:
            s_ip_addr = s_ip_addr.replace(sane_bytes('.'), sane_bytes(':'))
        if int(s_expire_time) > time_now and s_ip_addr == ip_addr and s_frame_platform == frame_platform:
            if sig == base64.urlsafe_b64encode(hmac.new(secret, msg=tosign, digestmod=hashlib.sha256).digest()):
                return True
        return False


if __name__ == '__main__':
    TEST_SECRET = 'asdffdsasdf'
    print(sign_session(1112, 'us', '12345abcd', 123456, 'asdffdsa', '123423234', 'ZZZZZYYYY', '123,321,23', '111222'))
    assert AnonID.verify(AnonID.create(1234, '1.2.3.4', 'fb', TEST_SECRET, 'salt'), 1233, '1.2.3.4', 'fb', TEST_SECRET)
    assert not AnonID.verify(AnonID.create(1234, '1.2.3.4', 'fb', TEST_SECRET, 'salt'), 1237, '1.2.3.4', 'fb', TEST_SECRET)
    assert not AnonID.verify(AnonID.create(1234, '1.2.3.4', 'fb', TEST_SECRET, 'salt'), 1233, '4.2.3.4', 'fb', TEST_SECRET)
    assert not AnonID.verify(AnonID.create(1234, '1.2.3.4', 'fb', TEST_SECRET, 'salt'), 1233, '1.2.3.4', 'fasdf', TEST_SECRET)
