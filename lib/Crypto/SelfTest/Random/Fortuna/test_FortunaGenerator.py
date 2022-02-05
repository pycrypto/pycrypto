# -*- coding: utf-8 -*-
#
#  SelfTest/Random/Fortuna/test_FortunaGenerator.py: Self-test for the FortunaGenerator module
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

"""Self-tests for Crypto.Random.Fortuna.FortunaGenerator"""

__revision__ = "$Id$"

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Util.py3compat import *

import unittest
from binascii import b2a_hex

class FortunaGeneratorTests(unittest.TestCase):
    def setUp(self):
        global FortunaGenerator
        from Crypto.Random.Fortuna import FortunaGenerator

    def test_generator(self):
        """FortunaGenerator.AESGenerator"""
        fg = FortunaGenerator.AESGenerator()

        # We shouldn't be able to read data until we've seeded the generator
        self.assertRaises(Exception, fg.pseudo_random_data, 1)
        self.assertEqual(0, fg.counter.next_value())

        # Seed the generator, which should set the key and increment the counter.
        fg.reseed(b("Hello"))
        self.assertEqual(b("eab9b62d526cd5a7336143d04515662d3fa401b17c0cf9f32445e3599a9df943"), b2a_hex(fg.key))
        self.assertEqual(1, fg.counter.next_value())

        # Read 2 full blocks from the generator
        self.assertEqual(b("5f63ebcfc920694f9684a545c6d5b975") +       # counter=1
                         b("7b77a2afc2431559d5d07c1e94b50d92"),        # counter=2
            b2a_hex(fg.pseudo_random_data(32)))

        # Meanwhile, the generator will have re-keyed itself and incremented its counter
        self.assertEqual(b("02d692cf000eba90ffbec7852d0d3406") +       # counter=3
                         b("edf9497965bc64a55414370502bd4136"),        # counter=4
            b2a_hex(fg.key))
        self.assertEqual(5, fg.counter.next_value())

        # Read another 2 blocks from the generator
        self.assertEqual(b("83876a74542bc86ee486ea1e86af9b6c") +       # counter=5
                         b("5106d63a651164767571d7e746b45b68"),        # counter=6
            b2a_hex(fg.pseudo_random_data(32)))


        # Try to read more than 2**20 bytes using the internal function.  This should fail.
        self.assertRaises(AssertionError, fg._pseudo_random_data, 2**20+1)

def get_tests(config={}):
    from Crypto.SelfTest.st_common import list_test_cases
    return list_test_cases(FortunaGeneratorTests)

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
