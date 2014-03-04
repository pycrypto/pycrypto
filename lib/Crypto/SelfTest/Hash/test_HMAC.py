# -*- coding: utf-8 -*-
#
#  SelfTest/Hash/HMAC.py: Self-test for the HMAC module
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

"""Self-test suite for Crypto.Hash.HMAC"""

__revision__ = "$Id$"

import unittest
from binascii import hexlify

from common import dict     # For compatibility with Python 2.1 and 2.2
from Crypto.Util.py3compat import *
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *

from Crypto.Hash import HMAC, MD5, SHA1, SHA256
hash_modules = dict(MD5=MD5, SHA1=SHA1, SHA256=SHA256)

try:
    from Crypto.Hash import SHA224, SHA384, SHA512, RIPEMD160
    hash_modules.update(dict(SHA224=SHA224, SHA384=SHA384, SHA512=SHA512,
                             RIPEMD160=RIPEMD160))
except ImportError:
    import sys
    sys.stderr.write("SelfTest: warning: not testing HMAC-SHA224/384/512"
                     " (not available)\n")

default_hash = None

def xl(text):
    return tostr(hexlify(b(text)))

# This is a list of (key, data, results, description) tuples.
test_data = [
    ## Test vectors from RFC 2202 ##
    # Test that the default hashmod is MD5
    ('0b' * 16,
        '4869205468657265',
        dict(default_hash='9294727a3638bb1c13f48ef8158bfc9d'),
        'default-is-MD5'),

    # Test case 1 (MD5)
    ('0b' * 16,
        '4869205468657265',
        dict(MD5='9294727a3638bb1c13f48ef8158bfc9d'),
        'RFC 2202 #1-MD5 (HMAC-MD5)'),

    # Test case 1 (SHA1)
    ('0b' * 20,
        '4869205468657265',
        dict(SHA1='b617318655057264e28bc0b6fb378c8ef146be00'),
        'RFC 2202 #1-SHA1 (HMAC-SHA1)'),

    # Test case 2
    ('4a656665',
        '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
        dict(MD5='750c783e6ab0b503eaa86e310a5db738',
            SHA1='effcdf6ae5eb2fa2d27416d5f184df9c259a7c79'),
        'RFC 2202 #2 (HMAC-MD5/SHA1)'),

    # Test case 3 (MD5)
    ('aa' * 16,
        'dd' * 50,
        dict(MD5='56be34521d144c88dbb8c733f0e8b3f6'),
        'RFC 2202 #3-MD5 (HMAC-MD5)'),

    # Test case 3 (SHA1)
    ('aa' * 20,
        'dd' * 50,
        dict(SHA1='125d7342b9ac11cd91a39af48aa17b4f63f175d3'),
        'RFC 2202 #3-SHA1 (HMAC-SHA1)'),

    # Test case 4
    ('0102030405060708090a0b0c0d0e0f10111213141516171819',
        'cd' * 50,
        dict(MD5='697eaf0aca3a3aea3a75164746ffaa79',
            SHA1='4c9007f4026250c6bc8414f9bf50c86c2d7235da'),
        'RFC 2202 #4 (HMAC-MD5/SHA1)'),

    # Test case 5 (MD5)
    ('0c' * 16,
        '546573742057697468205472756e636174696f6e',
        dict(MD5='56461ef2342edc00f9bab995690efd4c'),
        'RFC 2202 #5-MD5 (HMAC-MD5)'),

    # Test case 5 (SHA1)
    # NB: We do not implement hash truncation, so we only test the full hash here.
    ('0c' * 20,
        '546573742057697468205472756e636174696f6e',
        dict(SHA1='4c1a03424b55e07fe7f27be1d58bb9324a9a5a04'),
        'RFC 2202 #5-SHA1 (HMAC-SHA1)'),

    # Test case 6
    ('aa' * 80,
        '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a'
        + '65204b6579202d2048617368204b6579204669727374',
        dict(MD5='6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd',
            SHA1='aa4ae5e15272d00e95705637ce8a3b55ed402112'),
        'RFC 2202 #6 (HMAC-MD5/SHA1)'),

    # Test case 7
    ('aa' * 80,
        '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a'
        + '65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d'
        + '53697a652044617461',
        dict(MD5='6f630fad67cda0ee1fb1f562db3aa53e',
            SHA1='e8e99d0f45237d786d6bbaa7965c7808bbff1a91'),
        'RFC 2202 #7 (HMAC-MD5/SHA1)'),

    ## Test vectors from RFC 4231 ##
    # 4.2. Test Case 1
    ('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
        '4869205468657265',
        dict(SHA224='''
            896fb1128abbdf196832107cd49df33f
            47b4b1169912ba4f53684b22
            ''',
            SHA256='''
            b0344c61d8db38535ca8afceaf0bf12b
            881dc200c9833da726e9376c2e32cff7
            ''',
            SHA384='''
            afd03944d84895626b0825f4ab46907f
            15f9dadbe4101ec682aa034c7cebc59c
            faea9ea9076ede7f4af152e8b2fa9cb6
            ''',
            SHA512='''
            87aa7cdea5ef619d4ff0b4241a1d6cb0
            2379f4e2ce4ec2787ad0b30545e17cde
            daa833b7d6b8a702038b274eaea3f4e4
            be9d914eeb61f1702e696c203a126854
        '''),
        'RFC 4231 #1'),

    # 4.3. Test Case 2 - Test with a key shorter than the length of the HMAC
    # output.
    ('4a656665',
        '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
        dict(SHA224='''
            a30e01098bc6dbbf45690f3a7e9e6d0f
            8bbea2a39e6148008fd05e44
            ''',
            SHA256='''
            5bdcc146bf60754e6a042426089575c7
            5a003f089d2739839dec58b964ec3843
            ''',
            SHA384='''
            af45d2e376484031617f78d2b58a6b1b
            9c7ef464f5a01b47e42ec3736322445e
            8e2240ca5e69e2c78b3239ecfab21649
            ''',
            SHA512='''
            164b7a7bfcf819e2e395fbe73b56e0a3
            87bd64222e831fd610270cd7ea250554
            9758bf75c05a994a6d034f65f8f0e6fd
            caeab1a34d4a6b4b636e070a38bce737
        '''),
        'RFC 4231 #2'),

    # 4.4. Test Case 3 - Test with a combined length of key and data that is
    # larger than 64 bytes (= block-size of SHA-224 and SHA-256).
    ('aa' * 20,
        'dd' * 50,
        dict(SHA224='''
            7fb3cb3588c6c1f6ffa9694d7d6ad264
            9365b0c1f65d69d1ec8333ea
            ''',
            SHA256='''
            773ea91e36800e46854db8ebd09181a7
            2959098b3ef8c122d9635514ced565fe
            ''',
            SHA384='''
            88062608d3e6ad8a0aa2ace014c8a86f
            0aa635d947ac9febe83ef4e55966144b
            2a5ab39dc13814b94e3ab6e101a34f27
            ''',
            SHA512='''
            fa73b0089d56a284efb0f0756c890be9
            b1b5dbdd8ee81a3655f83e33b2279d39
            bf3e848279a722c806b485a47e67c807
            b946a337bee8942674278859e13292fb
        '''),
        'RFC 4231 #3'),

    # 4.5. Test Case 4 - Test with a combined length of key and data that is
    # larger than 64 bytes (= block-size of SHA-224 and SHA-256).
    ('0102030405060708090a0b0c0d0e0f10111213141516171819',
        'cd' * 50,
        dict(SHA224='''
            6c11506874013cac6a2abc1bb382627c
            ec6a90d86efc012de7afec5a
            ''',
            SHA256='''
            82558a389a443c0ea4cc819899f2083a
            85f0faa3e578f8077a2e3ff46729665b
            ''',
            SHA384='''
            3e8a69b7783c25851933ab6290af6ca7
            7a9981480850009cc5577c6e1f573b4e
            6801dd23c4a7d679ccf8a386c674cffb
            ''',
            SHA512='''
            b0ba465637458c6990e5a8c5f61d4af7
            e576d97ff94b872de76f8050361ee3db
            a91ca5c11aa25eb4d679275cc5788063
            a5f19741120c4f2de2adebeb10a298dd
        '''),
        'RFC 4231 #4'),

    # 4.6. Test Case 5 - Test with a truncation of output to 128 bits.
    #
    # Not included because we do not implement hash truncation.
    #

    # 4.7. Test Case 6 - Test with a key larger than 128 bytes (= block-size of
    # SHA-384 and SHA-512).
    ('aa' * 131,
        '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a'
        + '65204b6579202d2048617368204b6579204669727374',
        dict(SHA224='''
            95e9a0db962095adaebe9b2d6f0dbce2
            d499f112f2d2b7273fa6870e
            ''',
            SHA256='''
            60e431591ee0b67f0d8a26aacbf5b77f
            8e0bc6213728c5140546040f0ee37f54
            ''',
            SHA384='''
            4ece084485813e9088d2c63a041bc5b4
            4f9ef1012a2b588f3cd11f05033ac4c6
            0c2ef6ab4030fe8296248df163f44952
            ''',
            SHA512='''
            80b24263c7c1a3ebb71493c1dd7be8b4
            9b46d1f41b4aeec1121b013783f8f352
            6b56d037e05f2598bd0fd2215d6a1e52
            95e64f73f63f0aec8b915a985d786598
        '''),
        'RFC 4231 #6'),

    # 4.8. Test Case 7 - Test with a key and data that is larger than 128 bytes
    # (= block-size of SHA-384 and SHA-512).
    ('aa' * 131,
        '5468697320697320612074657374207573696e672061206c6172676572207468'
        + '616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074'
        + '68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565'
        + '647320746f20626520686173686564206265666f7265206265696e6720757365'
        + '642062792074686520484d414320616c676f726974686d2e',
        dict(SHA224='''
            3a854166ac5d9f023f54d517d0b39dbd
            946770db9c2b95c9f6f565d1''',
            SHA256='''
            9b09ffa71b942fcb27635fbcd5b0e944
            bfdc63644f0713938a7f51535c3a35e2
            ''',
            SHA384='''
            6617178e941f020d351e2f254e8fd32c
            602420feb0b8fb9adccebb82461e99c5
            a678cc31e799176d3860e6110c46523e
            ''',
            SHA512='''
            e37b6a775dc87dbaa4dfa9f96e5e3ffd
            debd71f8867289865df5a32d20cdc944
            b6022cac3c4982b10d5eeb55c3e4de15
            134676fb6de0446065c97440fa8c6a58
        '''),
        'RFC 4231 #7'),

    # Test case 11 (RIPEMD)
    ('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
     xl("Hi There"),
     dict(RIPEMD160='24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668'),
     'RFC 2286 #1 (HMAC-RIPEMD)'),

    # Test case 12 (RIPEMD)
    (xl("Jefe"),
     xl("what do ya want for nothing?"),
     dict(RIPEMD160='dda6c0213a485a9e24f4742064a7f033b43c4069'),
     'RFC 2286 #2 (HMAC-RIPEMD)'),

    # Test case 13 (RIPEMD)
    ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
     'dd' * 50,
     dict(RIPEMD160='b0b105360de759960ab4f35298e116e295d8e7c1'),
     'RFC 2286 #3 (HMAC-RIPEMD)'),

    # Test case 14 (RIPEMD)
    ('0102030405060708090a0b0c0d0e0f10111213141516171819',
     'cd' * 50,
     dict(RIPEMD160='d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4'),
     'RFC 2286 #4 (HMAC-RIPEMD)'),

    # Test case 15 (RIPEMD)
    ('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
     xl("Test With Truncation"),
     dict(RIPEMD160='7619693978f91d90539ae786500ff3d8e0518e39'),
     'RFC 2286 #5 (HMAC-RIPEMD)'),

    # Test case 16 (RIPEMD)
    ('aa' * 80,
     xl("Test Using Larger Than Block-Size Key - Hash Key First"),
     dict(RIPEMD160='6466ca07ac5eac29e1bd523e5ada7605b791fd8b'),
     'RFC 2286 #6 (HMAC-RIPEMD)'),

    # Test case 17 (RIPEMD)
    ('aa' * 80,
     xl("Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"),
     dict(RIPEMD160='69ea60798d71616cce5fd0871e23754cd75d5a0a'),
     'RFC 2286 #7 (HMAC-RIPEMD)'),

]


class HMAC_Module_and_Instance_Test(unittest.TestCase):
    """Test the HMAC construction and verify that it does not
    matter if you initialize it with a hash module or
    with an hash instance.

    See https://bugs.launchpad.net/pycrypto/+bug/1209399
    """

    def __init__(self, hashmods):
        """Initialize the test with a dictionary of hash modules
        indexed by their names"""

        unittest.TestCase.__init__(self)
        self.hashmods = hashmods
        self.description = ""

    def shortDescription(self):
        return self.description

    def runTest(self):
        key = b("\x90\x91\x92\x93") * 4
        payload = b("\x00") * 100

        for hashname, hashmod in self.hashmods.items():
            if hashmod is None:
                continue
            self.description = "Test HMAC in combination with " + hashname
            one = HMAC.new(key, payload, hashmod).digest()
            two = HMAC.new(key, payload, hashmod.new()).digest()
            self.assertEqual(one, two)


def get_tests(config={}):
    global test_data
    from common import make_mac_tests

    # A test vector contains multiple results, each one for a
    # different hash algorithm.
    # Here we expand each test vector into multiple ones,
    # and add the relevant parameters that will be passed to new()
    exp_test_data = []
    for row in test_data:
        for modname in row[2].keys():
            t = list(row)
            t[2] = row[2][modname]
            try:
                t.append(dict(digestmod=globals()[modname]))
                exp_test_data.append(t)
            except AttributeError:
                import sys
                sys.stderr.write("SelfTest: warning: not testing HMAC-%s"
                                 " (not available)\n" % modname)
    tests = make_mac_tests(HMAC, "HMAC", exp_test_data)
    tests.append(HMAC_Module_and_Instance_Test(hash_modules))
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
