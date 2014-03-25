# -*- coding: utf-8 -*-
#
# Hash/XCBCMAC.py - Implements the XCBC-MAC algorithm
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

__all__ = ['new', 'digest_size', 'XCBCMAC' ]

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Util.py3compat import *

from Crypto.Hash.CMAC import _SmoothMAC, CMAC

#: The size of the authentication tag produced by the MAC.
digest_size = None

class XCBCMAC(CMAC):
    """Older version of the CMAC algorithm that uses a different way to
    compute sub-keys.

    Reference from RFC 3566 - Section 4 (http://tools.ietf.org/html/rfc3566)

        Derive 3 128-bit keys (K1, K2 and K3) from the 128-bit secret
        key K, as follows:
        K1 = 0x01010101010101010101010101010101 encrypted with Key K
        K2 = 0x02020202020202020202020202020202 encrypted with Key K
        K3 = 0x03030303030303030303030303030303 encrypted with Key K

    This was checked with the test vectors provided in RFC 3566 - Section 4.6
    """
    def __init__(self, key, msg=None, ciphermod=None):
        CMAC.__init__(self, key, msg=msg, ciphermod=ciphermod)

        # MODE_ECB is to avoid propagation between blocks for the computation
        # of the sub-keys
        key_cipher = ciphermod.new(key, ciphermod.MODE_ECB)

        self._k0 = key_cipher.encrypt(bchr(1) * ciphermod.block_size)
        self._k1 = key_cipher.encrypt(bchr(2) * ciphermod.block_size)
        self._k2 = key_cipher.encrypt(bchr(3) * ciphermod.block_size)

        self._mac = ciphermod.new(self._k0, ciphermod.MODE_CBC, self._IV)

    def copy(self):
        """Return a copy ("clone") of the MAC object.

        The copy will have the same internal state as the original MAC
        object.
        This can be used to efficiently compute the MAC of strings that
        share a common initial substring.

        :Returns: A `XCBCMAC` object
        """
        obj = XCBCMAC(self._key, ciphermod=self._factory)

        _SmoothMAC._deep_copy(self, obj)

        for m in [ '_tag', '_IV']:
            setattr(obj, m, getattr(self, m))

        return obj

def new(key, msg=None, ciphermod=None):
    """Create a new XCBCMAC object.

    :Parameters:
        key : byte string
            secret key for the XCBCMAC object.
            The key must be valid for the underlying cipher algorithm.
            For instance, it must be 16 bytes long for AES-128.
        msg : byte string
            The very first chunk of the message to authenticate.
            It is equivalent to an early call to `XCBCMAC.update`. Optional.
        ciphermod : module
            A cipher module from `Crypto.Cipher`.
            The cipher's block size must be 64 or 128 bits.
            Default is `Crypto.Cipher.AES`.

    :Returns: A `XCBCMAC` object
    """
    return XCBCMAC(key, msg, ciphermod)
