# -*- coding: utf-8 -*-
#
#  SelfTest/PublicKey/test_PKCS8.py: Self-test for the PKCS8 module
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

"""Self-tests for Crypto.PublicKey.PKCS8 module"""

__revision__ = "$Id$"

import unittest
import sys

from Crypto.Util.py3compat import *
from Crypto.Util.asn1 import *
from Crypto.PublicKey import PKCS8
from binascii import *

if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *

oid_key = '1.2.840.113549.1.1.1'

# Original RSA key (in DER format)
# hexdump -v -e '32/1 "%02x" "\n"' key.der
clear_key="""
308201ab020100025a00b94a7f7075ab9e79e8196f47be707781e80dd965cf16
0c951a870b71783b6aaabbd550c0e65e5a3dfe15b8620009f6d7e5efec42a3f0
6fe20faeebb0c356e79cdec6db4dd427e82d8ae4a5b90996227b8ba54ccfc4d2
5c08050203010001025a00afa09c70d528299b7552fe766b5d20f9a221d66938
c3b68371d48515359863ff96f0978d700e08cd6fd3d8a3f97066fc2e0d5f78eb
3a50b8e17ba297b24d1b8e9cdfd18d608668198d724ad15863ef0329195dee89
3f039395022d0ebe0518df702a8b25954301ec60a97efdcec8eaa4f2e76ca7e8
8dfbc3f7e0bb83f9a0e8dc47c0f8c746e9df6b022d0c9195de13f09b7be1fdd7
1f56ae7d973e08bd9fd2c3dfd8936bb05be9cc67bd32d663c7f00d70932a0be3
c24f022d0ac334eb6cabf1933633db007b763227b0d9971a9ea36aca8b669ec9
4fcf16352f6b3dcae28e4bd6137db4ddd3022d0400a09f15ee7b351a2481cb03
09920905c236d09c87afd3022f3afc2a19e3b746672b635238956ee7e6dd62d5
022d0cd88ed14fcfbda5bbf0257f700147137bbab9c797af7df866704b889aa3
7e2e93df3ff1a0fd3490111dcdbc4c
"""

# Same key as above, wrapped in PKCS#8 but w/o password
#
# openssl pkcs8 -topk8 -inform DER -nocrypt -in key.der -outform DER -out keyp8.der
# hexdump -v -e '32/1 "%02x" "\n"' keyp8.der
wrapped_clear_key="""
308201c5020100300d06092a864886f70d0101010500048201af308201ab0201
00025a00b94a7f7075ab9e79e8196f47be707781e80dd965cf160c951a870b71
783b6aaabbd550c0e65e5a3dfe15b8620009f6d7e5efec42a3f06fe20faeebb0
c356e79cdec6db4dd427e82d8ae4a5b90996227b8ba54ccfc4d25c0805020301
0001025a00afa09c70d528299b7552fe766b5d20f9a221d66938c3b68371d485
15359863ff96f0978d700e08cd6fd3d8a3f97066fc2e0d5f78eb3a50b8e17ba2
97b24d1b8e9cdfd18d608668198d724ad15863ef0329195dee893f039395022d
0ebe0518df702a8b25954301ec60a97efdcec8eaa4f2e76ca7e88dfbc3f7e0bb
83f9a0e8dc47c0f8c746e9df6b022d0c9195de13f09b7be1fdd71f56ae7d973e
08bd9fd2c3dfd8936bb05be9cc67bd32d663c7f00d70932a0be3c24f022d0ac3
34eb6cabf1933633db007b763227b0d9971a9ea36aca8b669ec94fcf16352f6b
3dcae28e4bd6137db4ddd3022d0400a09f15ee7b351a2481cb0309920905c236
d09c87afd3022f3afc2a19e3b746672b635238956ee7e6dd62d5022d0cd88ed1
4fcfbda5bbf0257f700147137bbab9c797af7df866704b889aa37e2e93df3ff1
a0fd3490111dcdbc4c
"""

###
#
# The key above will now be encrypted with different algorithms.
# The password is always 'TestTest'.
#
# Each item in the wrapped_enc_keys list contains:
#  * wrap algorithm
#  * iteration count
#  * Salt
#  * IV
#  * Expected result
###
wrapped_enc_keys = []

#
# openssl pkcs8 -topk8 -passin pass:TestTest -inform DER -in key.der -outform DER -out keyenc.der -v2 des3
# hexdump -v -e '32/1 "%02x" "\n"' keyenc.der
#
wrapped_enc_keys.append((
'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC',
2048,
"47EA7227D8B22E2F", # IV
"E3F7A838AB911A4D", # Salt
"""
30820216304006092a864886f70d01050d3033301b06092a864886f70d01050c
300e0408e3f7a838ab911a4d02020800301406082a864886f70d0307040847ea
7227d8b22e2f048201d0ea388b374d2d0e4ceb7a5139f850fdff274884a6e6c0
64326e09d00dbba9018834edb5a51a6ae3d1806e6e91eebf33788ce71fee0637
a2ebf58859dd32afc644110c390274a6128b50c39b8d907823810ec471bada86
6f5b75d8ea04ad310fad2e73621696db8e426cd511ee93ec1714a1a7db45e036
4bf20d178d1f16bbb250b32c2d200093169d588de65f7d99aad9ddd0104b44f1
326962e1520dfac3c2a800e8a14f678dff2b3d0bb23f69da635bf2a643ac934e
219a447d2f4460b67149e860e54f365da130763deefa649c72b0dcd48966a2d3
4a477444782e3e66df5a582b07bbb19778a79bd355074ce331f4a82eb966b0c4
52a09eab6116f2722064d314ae433b3d6e81d2436e93fdf446112663cde93b87
9c8be44beb45f18e2c78fee9b016033f01ecda51b9b142091fa69f65ab784d2c
5ad8d34be6f7f1464adfc1e0ef3f7848f40d3bdea4412758f2fcb655c93d8f4d
f6fa48fc5aa4b75dd1c017ab79ac9d737233a6d668f5364ccf47786debd37334
9c10c9e6efbe78430a61f71c89948aa32cdc3cc7338cf994147819ce7ab23450
c8f7d9b94c3bb377d17a3fa204b601526317824b142ff6bc843fa7815ece89c0
839573f234dac8d80cc571a045353d61db904a4398d8ef3df5ac
"""
))

#
# openssl pkcs8 -topk8 -passin pass:TestTest -inform DER -in key.der -outform DER -out keyenc.der
# hexdump -v -e '32/1 "%02x" "\n"' keyenc.der
#
wrapped_enc_keys.append((
-1,                 # pbeWithMD5AndDES-CBC, only decoding is supported
-1,
"",
"",
"""
308201f1301b06092a864886f70d010503300e0408f9b990c89af1d41b020208
00048201d0c6267fe8592903891933d559e71a7ca68b2e39150f19daca0f7921
52f97e249d72f670d5140e9150433310ed7c7ee51927693fd39884cb9551cea5
a7b746f7edf199f8787d4787a35dad930d7db057b2118851211b645ac8b90fa6
b0e7d49ac8567cbd5fff226e87aa9129a0f52c45e9307752e8575c3b0ff756b7
31fda6942d15ecb6b27ea19370ccc79773f47891e80d22b440d81259c4c28eac
e0ca839524116bcf52d8c566e49a95ddb0e5493437279a770a39fd333f3fca91
55884fad0ba5aaf273121f893059d37dd417da7dcfd0d6fa7494968f13b2cc95
65633f2c891340193e5ec00e4ee0b0e90b3b93da362a4906360845771ade1754
9df79140be5993f3424c012598eadd3e7c7c0b4db2c72cf103d7943a5cf61420
93370b9702386c3dd4eb0a47f34b579624a46a108b2d13921fa1b367495fe345
6aa128aa70f8ca80ae13eb301e96c380724ce67c54380bbea2316c1faf4d058e
b4ca2e23442047606b9bc4b3bf65b432cb271bea4eb35dd3eb360d3be8612a87
a50e96a2264490aeabdc07c6e78e5dbf4fe3388726d0e2a228346bf3c2907d68
2a6276b22ae883fb30fa611f4e4193e7a08480fcd7db48308bacbd72bf4807aa
11fd394859f97d22982f7fe890b2e2a0f7e7ffb693
"""
))

def txt2bin(inputs):
    s = b('').join([b(x) for x in inputs if not (x in '\n\r\t ')])
    return unhexlify(s)

class Rng:
    def __init__(self, output):
        self.output=output
        self.idx=0
    def __call__(self, n):
        output = self.output[self.idx:self.idx+n]
        self.idx += n
        return output

class PKCS8_Decrypt(unittest.TestCase):

    def setUp(self):
        self.oid_key = oid_key
        self.clear_key = txt2bin(clear_key)
        self.wrapped_clear_key = txt2bin(wrapped_clear_key)
        self.wrapped_enc_keys = []
        for t in wrapped_enc_keys:
            self.wrapped_enc_keys.append((
                t[0],
                t[1],
                txt2bin(t[2]),
                txt2bin(t[3]),
                txt2bin(t[4])
            ))

    ### NO ENCRYTION

    def test1(self):
        """Verify unwrapping w/o encryption"""
        res1, res2, res3 = PKCS8.unwrap(self.wrapped_clear_key)
        self.assertEqual(res1, self.oid_key)
        self.assertEqual(res2, self.clear_key)

    def test2(self):
        """Verify wrapping w/o encryption"""
        wrapped = PKCS8.wrap(self.clear_key, self.oid_key, None)
        res1, res2, res3 = PKCS8.unwrap(wrapped)
        self.assertEqual(res1, self.oid_key)
        self.assertEqual(res2, self.clear_key)

    ## ENCRYPTION

    def test3(self):
        """Verify unwrapping with encryption"""

        for t in self.wrapped_enc_keys:
            res1, res2, res3 = PKCS8.unwrap(t[4], b("TestTest"))
            self.assertEqual(res1, self.oid_key)
            self.assertEqual(res2, self.clear_key)

    def test4(self):
        """Verify wrapping with encryption"""

        for t in self.wrapped_enc_keys:
            if t[0]==-1:
                continue
            rng = Rng(t[2]+t[3])
            params = { 'iteration_count':t[1] }
            wrapped = PKCS8.wrap(
                    self.clear_key,
                    self.oid_key,
                    b("TestTest"),
                    wrap_params=params,
                    randfunc=rng)
            self.assertEqual(wrapped, t[4])

def get_tests(config={}):
    from Crypto.SelfTest.st_common import list_test_cases
    listTests = []
    listTests += list_test_cases(PKCS8_Decrypt)
    return listTests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

