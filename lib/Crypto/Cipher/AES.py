# -*- coding: utf-8 -*-
#
#  Cipher/AES.py : AES
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
"""AES symmetric cipher

AES `(Advanced Encryption Standard)`__ is a symmetric block cipher standardized
by NIST_ . It has a fixed data block size of 16 bytes.
Its keys can be 128, 192, or 256 bits long.

AES is very fast and secure, and it is the de facto standard for symmetric
encryption.

As an example, encryption can be done as follows:

    >>> from Crypto.Cipher import AES
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>> key = b'Sixteen byte key'
    >>> iv = get_random_bytes(16)
    >>> cipher = AES.new(key, AES.MODE_CFB, iv)
    >>> msg = iv + cipher.encrypt(b'Attack at dawn')

A more complicated example is based on CCM, (see `MODE_CCM`) an `AEAD`_ mode
that provides both confidentiality and authentication for a message.
It also allows message for the header to remain in the clear, whilst still
being authenticated. The encryption is done as follows:

    >>> from Crypto.Cipher import AES
    >>> from Crypto.Random import get_random_bytes
    >>>
    >>>
    >>> hdr = b'To your eyes only'
    >>> plaintext = b'Attack at dawn'
    >>> key = b'Sixteen byte key'
    >>> nonce = get_random_bytes(11)
    >>> cipher = AES.new(key, AES.MODE_CCM, nonce)
    >>> cipher.update(hdr)
    >>> msg = nonce, hdr, cipher.encrypt(plaintext), cipher.digest()

We assume that the tuple ``msg`` is transmitted to the receiver:

    >>> nonce, hdr, ciphertext, mac = msg
    >>> key = b'Sixteen byte key'
    >>> cipher = AES.new(key, AES.MODE_CCM, nonce)
    >>> cipher.update(hdr)
    >>> plaintext = cipher.decrypt(ciphertext)
    >>> try:
    >>>     cipher.verify(mac)
    >>>     print "The message is authentic: hdr=%s, pt=%s" % (hdr, plaintext)
    >>> except ValueError:
    >>>     print "Key incorrect or message corrupted"

.. __: http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
.. _NIST: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
.. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
"""

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *

from Crypto.Cipher import _AES, _create_cipher
from Crypto.Util import cpuid
from Crypto.Util.parameters import pop_parameter

# Import _AESNI. If AES-NI is not available or _AESNI has not been built, set
# _AESNI to None.
try:
    if cpuid.have_aes_ni():
        from Crypto.Cipher import _AESNI
    else:
        _AESNI = None
except ImportError:
    _AESNI = None

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
#: Counter with CBC-MAC (CCM) Mode. See `ModeCCM`.
MODE_CCM = 8
#: EAX Mode. See `ModeEAX`.
MODE_EAX = 9
#: Syntethic Initialization Vector (SIV). See `ModeSIV`.
MODE_SIV = 10
#: Galois Counter Mode (GCM). See `ModeGCM`.
MODE_GCM = 11
#: Size of a data block (in bytes)
block_size = 16
#: Size of a key (in bytes)
key_size = ( 16, 24, 32 )

def new(key, mode=MODE_ECB, *args, **kwargs):
    """Create a new AES cipher.

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
    |  MODE_CCM      |  `ModeCCM`     |
    +----------------+----------------+
    |  MODE_EAX      |  `ModeEAX`     |
    +----------------+----------------+
    |  MODE_SIV      |  `ModeSIV`     |
    +----------------+----------------+
    |  MODE_GCM      |  `ModeGCM`     |
    +----------------+----------------+

    :Parameters:
      key : byte string
        The secret key to use in the symmetric cipher.
        It must be 16 (AES-128), 24 (AES-192)
        or 32 (AES-256) bytes long.

      mode : a *MODE_** constant
        The chaining mode to use for encryption or decryption.
        Default is `MODE_ECB`.

    :Return: a cipher mode object
    """

    args_2 = list(args)
    kwargs_2 = kwargs.copy()

    # Check if the use_aesni was specified.
    use_aesni = pop_parameter('use_aesni', -1, args_2, kwargs_2)

    # Use _AESNI if the user requested AES-NI and it's available
    if _AESNI is not None and use_aesni:
        aes_module = _AESNI
    else:
        aes_module = _AES

    return _create_cipher(aes_module, key, mode, 1, *args_2, **kwargs_2)
