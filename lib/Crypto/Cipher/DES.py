# -*- coding: utf-8 -*-
#
#  Cipher/DES.py : DES
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
"""DES symmetric cipher

DES `(Data Encryption Standard)`__ is a symmetric block cipher standardized
by NIST_ . It has a fixed data block size of 8 bytes.
Its keys are 64 bits long, even though 8 bits were used for integrity (now they
are ignored) and do not contribute to securty.

DES is cryptographically secure, but its key length is too short by nowadays
standards and it could be brute forced with some effort.

DES should not be used for new designs. Use `AES`.

As an example, encryption can be done as follows:

    >>> from Crypto.Cipher import DES
    >>> from Crypto import Random
    >>>
    >>> key = b'-8B key-'
    >>> iv = Random.new().read(DES.block_size)
    >>> cipher = DES.new(key, DES.MODE_OFB, iv)
    >>> plaintext = b'sona si latine loqueris '
    >>> msg = iv + cipher.encrypt(plaintext)

.. __: http://en.wikipedia.org/wiki/Data_Encryption_Standard
.. _NIST: http://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf
"""

from Crypto.Cipher import _DES, _create_cipher
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
key_size = 8

def new(key, mode=MODE_ECB, *args, **kwargs):
    """Create a new DES cipher.

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
        It is 8 bytes long. Parity bits are ignored.

      mode : a *MODE_** constant
        The chaining mode to use for encryption or decryption.
        Default is `MODE_ECB`.

    :Return: a cipher mode object
    """

    return _create_cipher(_DES, key, mode, 0, *args, **kwargs)

