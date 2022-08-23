#!/usr/bin/env python

# Copyright (c) 2022 Battlehouse Inc. All rights reserved.
# Use of this source code is governed by an MIT-style license that can be
# found in the LICENSE file.

# Safe handling of functions and data types changed between Python2/Python3

import json
from six import PY2
from six import PY3
if PY3:
    basestring = str
    unicode = str


def iteritems(data):
    '''
    iterates through dictionary items
    '''
    if PY2:
        return data.iteritems()
    return iter(data.items())


def iterkeys(data):
    '''
    iterates through dictionary keys
    '''
    if PY2:
        return data.iterkeys()
    return iter(data.keys())


def itervalues(data):
    '''
    iterates through dictionary values
    '''
    if PY2:
        return data.itervalues()
    return iter(data.values())


def sane_bytes(input, coding='ascii'):
    '''
    ensures that input is properly encoded as bytes regardless of platform
    '''
    if isinstance(input, bytes):
        return input
    if PY2:
        if not isinstance(input, basestring):
            input = str(input)
        if isinstance(input, unicode):
            if coding == 'ascii':
                input = bytes(input)
            else:
                input = input.encode(coding)
        return input
    input = bytes(input, coding)
    return input


def sane_str(output):
    '''
    ensures that output is encoded as a string without type-indicator prefixes like b''
    '''
    if not isinstance(output, basestring):
        output = str(output)
    if PY2:
        return output
    output = output.replace("b'", '')
    output = output.replace('b"', '')
    output = output.replace("'", '')
    if not is_json_str(output):
        output = output.replace('"', '')
    return output


def sane_mapping(input, mapping):
    '''
    ensures that base64 URL encoding is mapped consistently across platforms
    '''
    input = sane_str(input)
    if PY2:
        input = unicode(input)
    return input.translate(mapping)


def sane_obj(input):
    '''
    ensures that requests and request-like objects are handled consistently across platforms
    '''
    if isinstance(input, dict):
        ret = {}
        for key, val in iteritems(input):
            ret[sane_str(key)] = sane_obj(val)
        return ret
    elif isinstance(input, list):
        ret = []
        for val in input:
            ret.append(sane_obj(val))
    elif isinstance(input, basestring):
        return sane_str(input)
    elif isinstance(input, bytes):
        return sane_str(input)
    else:
        return input


def is_json_str(input):
    '''
    checks if string is a json string before stripping double-quotes
    '''
    try:
        json.loads(input)
        return True
    except BaseException:
        return False
