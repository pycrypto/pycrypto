# -*- coding: utf-8 -*-
#
#  SelfTest/Random/Fortuna/test_FortunaAccumulator.py: Self-test for the FortunaAccumulator module
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

"""Self-tests for Crypto.Random.Fortuna.FortunaAccumulator"""

__revision__ = "$Id$"

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Util.py3compat import *
from Crypto.SelfTest.st_common import assert_disabled

import unittest
from binascii import b2a_hex

class FortunaAccumulatorTests(unittest.TestCase):
    def setUp(self):
        global FortunaAccumulator
        from Crypto.Random.Fortuna import FortunaAccumulator

    def test_FortunaPool(self):
        """FortunaAccumulator.FortunaPool"""
        pool = FortunaAccumulator.FortunaPool()
        self.assertEqual(0, pool.length)
        self.assertEqual("e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9", pool.hexdigest())

        pool.append(b('abc'))

        self.assertEqual(3, pool.length)
        self.assertEqual("4f16deb3ad853b88d8585b018319ad61455c1aba98a77a72b8fd324cbf0e775a", pool.hexdigest())

        pool.append(b("dbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))

        self.assertEqual(56, pool.length)
        self.assertEqual(b('be2784995e38d67e07716d73e49d920bdafcc426a0be4cbb42731577c3921a6f'), b2a_hex(pool.digest()))

        pool.reset()

        self.assertEqual(0, pool.length)

        pool.append(b('a') * 10**6)

        self.assertEqual(10**6, pool.length)
        self.assertEqual(b('15b85d650262b236772f3057dd950fade220b69c15c1cb01343122ae2760c143'), b2a_hex(pool.digest()))

    def test_which_pools(self):
        """FortunaAccumulator.which_pools"""

        # which_pools(0) should trigger an assertion failure (unless using -O or -OO)
        if not assert_disabled():
            self.assertRaises(AssertionError, FortunaAccumulator.which_pools, 0)

        self.assertEqual(FortunaAccumulator.which_pools(1), [0])
        self.assertEqual(FortunaAccumulator.which_pools(2), [0, 1])
        self.assertEqual(FortunaAccumulator.which_pools(3), [0])
        self.assertEqual(FortunaAccumulator.which_pools(4), [0, 1, 2])
        self.assertEqual(FortunaAccumulator.which_pools(5), [0])
        self.assertEqual(FortunaAccumulator.which_pools(6), [0, 1])
        self.assertEqual(FortunaAccumulator.which_pools(7), [0])
        self.assertEqual(FortunaAccumulator.which_pools(8), [0, 1, 2, 3])
        for i in range(1, 32):
            self.assertEqual(FortunaAccumulator.which_pools(2L**i-1), [0])
            self.assertEqual(FortunaAccumulator.which_pools(2L**i), range(i+1))
            self.assertEqual(FortunaAccumulator.which_pools(2L**i+1), [0])
        self.assertEqual(FortunaAccumulator.which_pools(2L**31), range(32))
        self.assertEqual(FortunaAccumulator.which_pools(2L**32), range(32))
        self.assertEqual(FortunaAccumulator.which_pools(2L**33), range(32))
        self.assertEqual(FortunaAccumulator.which_pools(2L**34), range(32))
        self.assertEqual(FortunaAccumulator.which_pools(2L**35), range(32))
        self.assertEqual(FortunaAccumulator.which_pools(2L**36), range(32))
        self.assertEqual(FortunaAccumulator.which_pools(2L**64), range(32))
        self.assertEqual(FortunaAccumulator.which_pools(2L**128), range(32))

    def test_accumulator(self):
        """FortunaAccumulator.FortunaAccumulator"""
        fa = FortunaAccumulator.FortunaAccumulator()

        # This should fail, because we haven't seeded the PRNG yet
        self.assertRaises(AssertionError, fa.random_data, 1)

        # Spread some test data across the pools (source number 42)
        # This would be horribly insecure in a real system.
        for p in range(32):
            fa.add_random_event(42, p, b("X") * 32)
            self.assertEqual(32+2, fa.pools[p].length)

        # This should still fail, because we haven't seeded the PRNG with 64 bytes yet
        self.assertRaises(AssertionError, fa.random_data, 1)

        # Add more data
        for p in range(32):
            fa.add_random_event(42, p, b("X") * 32)
            self.assertEqual((32+2)*2, fa.pools[p].length)

        # The underlying RandomGenerator should get seeded with Pool 0
        #   s = SHAd256(chr(42) + chr(32) + "X"*32 + chr(42) + chr(32) + "X"*32)
        #     = SHA256(h'751e1b2b1b2d2b6ef2ce5b8ce41154691296603c7e9b04ad273559108d07842f')
        #     = h'f83cbaf31e58f62ca1d57962783c70b5e7ae74e7c1ef816b1ac5198e5fae7b79'
        # The counter and the key before reseeding is:
        #   C_0 = 0
        #   K_0 = "\x00" * 32
        # The counter after reseeding is 1, and the new key after reseeding is
        #   C_1 = 1
        #   K_1 = SHAd256(K_0 || s)
        #       = SHA256(h'85ae0ca55db8bffe7c2b50d4b7ed2c1b792d77c5c8a4239b9a55165af276547e')
        #       = h'7296a62009939621e0c078836dec83e2061821f31ba01672b57173fbe8baf9f1'
        # The first block of random data, therefore, is
        #   r_1 = AES-256(K_1, 1)
        #       = AES-256(K_1, h'01000000000000000000000000000000')
        #       = h'd4e0f092630f6882849795b07bca624e'
        # The second block of random data is
        #   r_2 = AES-256(K_1, 2)
        #       = AES-256(K_1, h'02000000000000000000000000000000')
        #       = h'cac3f5007dbea003102d26c2d5537ad6'
        # The third and fourth blocks of random data (which become the new key) are
        #   r_3 = AES-256(K_1, 3)
        #       = AES-256(K_1, h'03000000000000000000000000000000')
        #       = h'f1b725f870e604499270b5ba978de45f'
        #   r_4 = AES-256(K_1, 4)
        #       = AES-256(K_1, h'04000000000000000000000000000000')
        #       = h'a4d1c10ee72e0c40122cf7579d90b489'
        #   K_2 = r_3 || r_4
        #       = h'f1b725f870e604499270b5ba978de45fa4d1c10ee72e0c40122cf7579d90b489'
        # The final counter value is 5.
        self.assertEqual("f83cbaf31e58f62ca1d57962783c70b5e7ae74e7c1ef816b1ac5198e5fae7b79",
            fa.pools[0].hexdigest())
        self.assertEqual(None, fa.generator.key)
        self.assertEqual(0, fa.generator.counter.next_value())

        result = fa.random_data(32)

        self.assertEqual(b("d4e0f092630f6882849795b07bca624e" "cac3f5007dbea003102d26c2d5537ad6"), b2a_hex(result))
        self.assertEqual(b("f1b725f870e604499270b5ba978de45f" "a4d1c10ee72e0c40122cf7579d90b489"), b2a_hex(fa.generator.key))
        self.assertEqual(5, fa.generator.counter.next_value())

    def test_accumulator_pool_length(self):
        """FortunaAccumulator.FortunaAccumulator minimum pool length"""
        fa = FortunaAccumulator.FortunaAccumulator()

        # This test case is hard-coded to assume that FortunaAccumulator.min_pool_size is 64.
        self.assertEqual(fa.min_pool_size, 64)

        # The PRNG should not allow us to get random data from it yet
        self.assertRaises(AssertionError, fa.random_data, 1)

        # Add 60 bytes, 4 at a time (2 header + 2 payload) to each of the 32 pools
        for i in range(15):
            for p in range(32):
                # Add the bytes to the pool
                fa.add_random_event(2, p, b("XX"))

                # The PRNG should not allow us to get random data from it yet
                self.assertRaises(AssertionError, fa.random_data, 1)

        # Add 4 more bytes to pool 0
        fa.add_random_event(2, 0, b("XX"))

        # We should now be able to get data from the accumulator
        fa.random_data(1)

def get_tests(config={}):
    from Crypto.SelfTest.st_common import list_test_cases
    return list_test_cases(FortunaAccumulatorTests)

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
