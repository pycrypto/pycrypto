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
import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
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
    from distutils.sysconfig import get_config_var
    import inspect, os.path
    ext_suffix = get_config_var("EXT_SUFFIX") or get_config_var("SO")
    _fm_path = os.path.normpath(os.path.dirname(os.path.abspath(
        inspect.getfile(inspect.currentframe())))
        +"/../../PublicKey/_fastmath"+ext_suffix)
    if os.path.exists(_fm_path):
        raise ImportError("While the _fastmath module exists, importing "+
            "it failed. This may point to the gmp or mpir shared library "+
            "not being in the path. _fastmath was found at "+_fm_path)

# vim:set ts=4 sw=4 sts=4 expandtab:
