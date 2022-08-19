#!/usr/bin/env python

# Copyright (c) 2022 Battlehouse Inc. All rights reserved.
# Use of this source code is governed by an MIT-style license that can be
# found in the LICENSE file.

# Safe handling of functions changed between Python2/Python3

from six import PY2


def iteritems(data):
    if PY2:
        return data.iteritems()
    return iter(data.items())


def iterkeys(data):
    if PY2:
        return data.iterkeys()
    return iter(data.keys())


def itervalues(data):
    if PY2:
        return data.itervalues()
    return iter(data.values())
