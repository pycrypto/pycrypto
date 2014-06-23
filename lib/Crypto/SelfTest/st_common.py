# -*- coding: utf-8 -*-
#
#  SelfTest/st_common.py: Common functions for SelfTest modules
#
# Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
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

"""Common functions for SelfTest modules"""

__revision__ = "$Id$"

import unittest
import binascii
from Crypto.Util.py3compat import *

class _list_testloader(unittest.TestLoader):
    suiteClass = list

def list_test_cases(class_):
    """Return a list of TestCase instances given a TestCase class

    This is useful when you have defined test* methods on your TestCase class.
    """
    return _list_testloader().loadTestsFromTestCase(class_)

def strip_whitespace(s):
    """Remove whitespace from a text or byte string"""
    if isinstance(s,str):
        return b("".join(s.split()))
    else:
        return b("").join(s.split())

def a2b_hex(s):
    """Convert hexadecimal to binary, ignoring whitespace"""
    return binascii.a2b_hex(strip_whitespace(s))

def b2a_hex(s):
    """Convert binary to hexadecimal"""
    # For completeness
    return binascii.b2a_hex(s)

def handle_fastmath_import_error():
    import Crypto.PublicKey
    import imp
    try:
        file, pathname, description = imp.find_module("_fastmath", Crypto.PublicKey.__path__)
    except ImportError:
        sys.stderr.write("SelfTest: warning: not testing _fastmath module (not available)\n")
    else:
        file.close()
        raise ImportError("While the _fastmath module exists, importing "
            "it failed. This may point to the gmp or mpir shared library "
            "not being in the path. _fastmath was found at %s" % (pathname,))

def docstrings_disabled():
    """Returns True if docstrings are disabled (e.g. by using python -OO)"""
    return docstrings_disabled.__doc__ is None

def assert_disabled():
    """Returns True if 'assert' is a no-op (e.g. by using python -O)"""
    try:
        assert False
    except AssertionError:
        return False
    else:
        return True

# vim:set ts=4 sw=4 sts=4 expandtab:
