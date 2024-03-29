#!/usr/bin/env python

# Copyright (c) 2022 Battlehouse Inc. All rights reserved.
# Use of this source code is governed by an MIT-style license that can be
# found in the LICENSE file.

# HTTP Accept-Languge parsing
# SP3RDPARTY : https://github.com/Babylonpartners/parse-accept-language/ : Apache License

import re

from collections import namedtuple
from operator import attrgetter

VALIDATE_LANG_REGEX = re.compile('^[a-z]+$', flags=re.IGNORECASE)
QUALITY_VAL_SUB_REGEX = re.compile('^q=', flags=re.IGNORECASE)
DEFAULT_QUALITY_VALUE = 1.0
MAX_HEADER_LEN = 8192
Lang = namedtuple('Lang', ('language', 'locale', 'quality'))


def parse_accept_language(accept_language_str, default_quality=None):
    '''
    Parse a RFC 2616 Accept-Language string.
    https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14
    :param accept_language_str: A string in RFC 2616 format.
    :type accept_language_str: str
    :returns: List of `Lang` namedtuples.
    :rtype: list
    :Example:
        >>> parse_accept_language('en-US,el;q=0.8')
        [
            Lang(locale='en_US', language='en', quality=1.0),
            Lang(locale=None, language='el', quality=0.8),
        ]
    '''
    if not accept_language_str:
        return []

    if len(accept_language_str) > MAX_HEADER_LEN:
        raise ValueError('Accept-Language too long, max length is 8192')

    parsed_langs = []
    for accept_lang_segment in accept_language_str.split(','):
        quality_value = default_quality or DEFAULT_QUALITY_VALUE
        lang_code = accept_lang_segment.strip()
        if ';' in accept_lang_segment:
            lang_code, quality_value = map(lambda x: x.strip(), accept_lang_segment.split(';'))
            quality_value = float(QUALITY_VAL_SUB_REGEX.sub('', quality_value))

        lang_code_components = re.split('-|_', lang_code)
        if not all(VALIDATE_LANG_REGEX.match(c) for c in lang_code_components):
            continue

        if len(lang_code_components) == 1:
            # language code 2/3 letters, e.g. fr
            language = lang_code_components[0].lower()
            locale = None
        else:
            # full language tag, e.g. en-US
            language = lang_code_components[0].lower()
            locale = '{}_{}'.format(
                language, lang_code_components[1].upper(),
            )
        parsed_langs.append(
            Lang(locale=locale, language=language, quality=quality_value)
        )
    return sorted(parsed_langs, key=attrgetter('quality'), reverse=True)
