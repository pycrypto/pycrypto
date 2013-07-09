# -*- coding: utf-8 -*-
#
#  SelfTest/Util/test_comparison.py: Self-test for the Crypto.Util.comparison module
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

"""Self-tests for Crypto.Util.comparison"""

__revision__ = "$Id$"

import unittest
from Crypto.Util.comparison import constant_time_comparison


class ConstantTimeComparisonTests(unittest.TestCase):
    def test_comparison_true(self):
        values = (
            '',
            '1',
            'a',
            'T\xfd\\\x97+;8Z\r\xad\x89\x95\xe7\xa8\x1cg',
        )
        for x in values:
            self.assertTrue(constant_time_comparison(x, x))

    def test_comparison_false(self):
        pairs = (
            ('short', 'long'),
            ('1234', '1224'),
            ('abcd', 'abcc'),
            ('bbcd', 'abcd'),
            ('T\xfd\\\x97+;8Z\r\xad\x89\x95\xe7\xa8\x1cc',
                'T\xfd\\\x97+;8Z\r\xad\x89\x95\xe7\xa8\x1cg'),
            ('S\xfd\\\x97+;8Z\r\xad\x89\x95\xe7\xa8\x1cg',
                'T\xfd\\\x97+;8Z\r\xad\x89\x95\xe7\xa8\x1cg'),
        )
        for x, y in pairs:
            self.assertFalse(constant_time_comparison(x, y))


def get_tests(config={}):
    from Crypto.SelfTest.st_common import list_test_cases
    listTests = []
    listTests += list_test_cases(ConstantTimeComparisonTests)
    return listTests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
