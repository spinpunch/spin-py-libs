#!/usr/bin/env python

# Copyright (c) 2022 Battlehouse Inc. All rights reserved.
# Use of this source code is governed by an MIT-style license that can be
# found in the LICENSE file.

# Safe handling of functions changed between Python2/Python3

try:
    dict.iteritems
except AttributeError:
    def iteritems(data):
        return iter(data.items())
    def iterkeys(data):
        return iter(data.keys())
    def itervalues(data):
        return iter(data.values())
else:
    def iteritems(data):
        return data.iteritems()
    def iterkeys(data):
        return data.iterkeys()
    def itervalues(data):
        return data.itervalues()
