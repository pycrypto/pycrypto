# -*- coding: utf-8 -*-
#
#  Cipher/DES3.py : DES3
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
"""Triple DES symmetric cipher

`Triple DES`__ (or TDES or TDEA or 3DES) is a symmetric block cipher standardized by NIST_.
It has a fixed data block size of 8 bytes. Its keys are 128 (*Option 1*) or 192
bits (*Option 2*) long.
However, 1 out of 8 bits is used for redundancy and do not contribute to
security. The effective key length is respectively 112 or 168 bits.

TDES consists of the concatenation of 3 simple `DES` ciphers.

The plaintext is first DES encrypted with *K1*, then decrypted with *K2*,
and finally encrypted again with *K3*.  The ciphertext is decrypted in the reverse manner.

The 192 bit key is a bundle of three 64 bit independent subkeys: *K1*, *K2*, and *K3*.

The 128 bit key is split into *K1* and *K2*, whereas *K1=K3*.

It is important that all subkeys are different, otherwise TDES would degrade to
single `DES`.

TDES is cryptographically secure, even though it is neither as secure nor as fast
as `AES`.

As an example, encryption can be done as follows:

    >>> from Crypto.Cipher import DES3
    >>> from Crypto import Random
    >>> from Crypto.Util import Counter
    >>>
    >>> key = b'Sixteen byte key'
    >>> nonce = Random.new().read(DES3.block_size/2)
    >>> ctr = Counter.new(DES3.block_size*8/2, prefix=nonce)
    >>> cipher = DES3.new(key, DES3.MODE_CTR, counter=ctr)
    >>> plaintext = b'We are no longer the knights who say ni!'
    >>> msg = nonce + cipher.encrypt(plaintext)

.. __: http://en.wikipedia.org/wiki/Triple_DES
.. _NIST: http://csrc.nist.gov/publications/nistpubs/800-67/SP800-67.pdf
"""

from Crypto.Cipher import _DES3, _create_cipher
from Crypto.Util.parameters import pop_parameter

#: Electronic Code Book (ECB). See `ModeECB`.
MODE_ECB = 1
#: Cipher-Block Chaining (CBC). See `ModeECB`.
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
key_size = ( 16, 24 )

def new(key, mode, *args, **kwargs):
    """Create a new TDES cipher.

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
        Its length can be 16 or 24 bytes.
        Parity bits are ignored.

      mode : a *MODE_** constant
        The chaining mode to use for encryption or decryption.
        Default is `MODE_ECB`.

    :Return: a cipher mode object
    """

    return _create_cipher(_DES3, key, mode, 0, *args, **kwargs)

