# -*- coding: utf-8 -*-
#
#  Cipher/Blowfish.py : Blowfish
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
"""Blowfish symmetric cipher

Blowfish_ is a symmetric block cipher designed by Bruce Schneier.

It has a fixed data block size of 8 bytes and its keys can vary in length
from 32 to 448 bits (4 to 56 bytes).

Blowfish is deemed secure and it is fast. However, its keys should be chosen
to be big enough to withstand a brute force attack (e.g. at least 16 bytes).

As an example, encryption can be done as follows:

    >>> from Crypto.Cipher import Blowfish
    >>> from Crypto import Random
    >>> from struct import pack
    >>>
    >>> bs = Blowfish.block_size
    >>> key = b'An arbitrarily long key'
    >>> iv = Random.new().read(bs)
    >>> cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    >>> plaintext = b'docendo discimus '
    >>> plen = bs - divmod(len(plaintext),bs)[1]
    >>> padding = [plen]*plen
    >>> padding = pack('b'*plen, *padding)
    >>> msg = iv + cipher.encrypt(plaintext + padding)

.. _Blowfish: http://www.schneier.com/blowfish.html
"""

from Crypto.Cipher import _Blowfish, _create_cipher
from Crypto.Util.parameters import pop_parameter

#: Electronic Code Book (ECB). See `ModeECB`.
MODE_ECB = 1
#: Cipher-Block Chaining (CBC). See `ModeCBC`.
MODE_CBC = 2
#: Cipher FeedBack (CFB). See `ModeCFB`.
MODE_CFB = 3
#: This mode should not be used.
MODE_PGP = 4
#: Output FeedBack (OFB). See `ModeOFB`.
MODE_OFB = 5
#: CounTer Mode (CTR). See `ModeCTR`.
MODE_CTR = 6
#: OpenPGP Mode. See `ModeOpenPGP`.
MODE_OPENPGP = 7
#: EAX Mode. See `ModeEAX`.
MODE_EAX = 9
#: Size of a data block (in bytes)
block_size = 8
#: Size of a key (in bytes)
key_size = xrange(4,56+1)

def new(key, mode=MODE_ECB, *args, **kwargs):
    """Create a new Blowfish cipher.

    Beside the parameters listed below, the function
    may also accept (or require) some mode-specific
    keyword arguments.

    The keywords are the same ones used to initialize
    the relevant mode object.

    +----------------+----------------+
    |  Mode value    |  Mode object   |
    +----------------+----------------+
    |  MODE_ECB      |  `ModeECB`     |
    +----------------+----------------+
    |  MODE_CBC      |  `ModeCBC`     |
    +----------------+----------------+
    |  MODE_CFB      |  `ModeCFB`     |
    +----------------+----------------+
    |  MODE_OFB      |  `ModeOFB`     |
    +----------------+----------------+
    |  MODE_CTR      |  `ModeCTR`     |
    +----------------+----------------+
    |  MODE_OPENPGP  |  `ModeOpenPGP` |
    +----------------+----------------+
    |  MODE_EAX      |  `ModeEAX`     |
    +----------------+----------------+

    :Parameters:
      key : byte string
        The secret key to use in the symmetric cipher.
        Its length can vary from 4 to 56 bytes.

      mode : a *MODE_** constant
        The chaining mode to use for encryption or decryption.
        Default is `MODE_ECB`.

    :Return: a cipher mode object
    """

    return _create_cipher(_Blowfish, key, mode, 0, *args, **kwargs)

