# -*- coding: utf-8 -*-
#
#  Cipher/CAST.py : CAST
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
"""CAST-128 symmetric cipher

CAST-128_ (or CAST5) is a symmetric block cipher specified in RFC2144_.

It has a fixed data block size of 8 bytes. Its key can vary in length
from 40 to 128 bits.

CAST is deemed to be cryptographically secure, but its usage is not widespread.
Keys of sufficient length should be used to prevent brute force attacks
(128 bits are recommended).

As an example, encryption can be done as follows:

    >>> from Crypto.Cipher import CAST
    >>> from Crypto import Random
    >>>
    >>> key = b'Sixteen byte key'
    >>> iv = Random.new().read(CAST.block_size)
    >>> cipher = CAST.new(key, CAST.MODE_OPENPGP, iv)
    >>> plaintext = b'sona si latine loqueris '
    >>> msg = cipher.encrypt(plaintext)
    >>>
    ...
    >>> eiv = msg[:CAST.block_size+2]
    >>> ciphertext = msg[CAST.block_size+2:]
    >>> cipher = CAST.new(key, CAST.MODE_OPENPGP, eiv)
    >>> print cipher.decrypt(ciphertext)

.. _CAST-128: http://en.wikipedia.org/wiki/CAST-128
.. _RFC2144: http://tools.ietf.org/html/rfc2144
"""

from Crypto.Cipher import _CAST, _create_cipher
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
key_size = xrange(5,16+1)

def new(key, mode=MODE_ECB, *args, **kwargs):
    """Create a new CAST cipher.

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
        Its length can vary from 5 to 16 bytes.

      mode : a *MODE_** constant
        The chaining mode to use for encryption or decryption.
        Default is `MODE_ECB`.

    :Return: a cipher mode object
    """

    return _create_cipher(_CAST, key, mode, 0, *args, **kwargs)

