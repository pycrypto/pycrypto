# -*- coding: utf-8 -*-
#
#  SelfTest/Hash/test_XCBCMAC.py: Self-test for the XCBCMAC module
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

"""Self-test suite for Crypto.Hash.XCBCMAC"""

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Util.py3compat import *

from common import dict

from Crypto.Hash import XCBCMAC
from Crypto.Cipher import AES

# This is a list of (key, data, result, description, module) tuples.
test_data = [
    (
        '000102030405060708090a0b0c0d0e0f',
        '',
        '75f0251d528ac01c4573dfd584d79f29',
        'RFC 3566 #1',
        AES
    ),

    (
        '000102030405060708090a0b0c0d0e0f',
        '000102',
        '5b376580ae2f19afe7219ceef172756f',
        'RFC 3566 #2',
        AES
    ),

    (
        '000102030405060708090a0b0c0d0e0f',
        '000102030405060708090a0b0c0d0e0f',
        'd2a246fa349b68a79998a4394ff7a263',
        'RFC 3566 #3',
        AES
    ),

    (
        '000102030405060708090a0b0c0d0e0f',
        '000102030405060708090a0b0c0d0e0f10111213',
        '47f51b4564966215b8985c63055ed308',
        'RFC 3566 #4',
        AES
    ),

    (
        '000102030405060708090a0b0c0d0e0f',
        '000102030405060708090a0b0c0d0e0f10111213141516171819' +
        '1a1b1c1d1e1f',
        'f54f0ec8d2b9f3d36807734bd5283fd4',
        'RFC 3566 #5',
        AES
    ),

    (
        '000102030405060708090a0b0c0d0e0f',
        '000102030405060708090a0b0c0d0e0f10111213141516171819' +
        '1a1b1c1d1e1f2021',
        'becbb3bccdb518a30677d5481fb6b4d8',
        'RFC 3566 #6',
        AES
    ),

    (
        '000102030405060708090a0b0c0d0e0f',
        '00' * 1000,
        'f0dafee895db30253761103b5d84528f',
        'RFC 3566 #7',
        AES
    ),
]

def get_tests(config={}):
    global test_data
    from common import make_mac_tests

    # Add new() parameters to the back of each test vector
    params_test_data = []
    for row in test_data:
        t = list(row)
        t[4] = dict(ciphermod=t[4])
        params_test_data.append(t)

    return make_mac_tests(XCBCMAC, "XCBCMAC", params_test_data)

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')
