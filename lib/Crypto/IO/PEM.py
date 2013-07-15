# -*- coding: ascii -*-
#
#  Util/PEM.py : Privacy Enhanced Mail utilities
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
"""Set of functions for encapsulating data according to the PEM format.

PEM (Privacy Enhanced Mail) was an IETF standard for securing emails via a
Public Key Infrastructure. It is specified in RFC 1421-1424.

Even though it has been abandoned, the simple message encapsulation it defined
is still widely used today for encoding *binary* cryptographic objects like
keys and certificates into text.
"""

__all__ = ['encode', 'decode']

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Util.py3compat import *

import re
from binascii import hexlify, unhexlify, a2b_base64, b2a_base64

from Crypto.Hash import MD5
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES, DES3, AES
from Crypto.Protocol.KDF import PBKDF1
from Crypto.Random import get_random_bytes


def encode(data, marker, passphrase=None, randfunc=None):
    """Encode a piece of binary data into PEM format.

    :Parameters:
      data : byte string
        The piece of binary data to encode.
      marker : string
        The marker for the PEM block (e.g. "PUBLIC KEY").
        Note that there is no official master list for all allowed markers.
        Still, you can refer to the OpenSSL_ source code.
      passphrase : byte string
        If given, the PEM block will be encrypted. The key is derived from
        the passphrase.
      randfunc : callable
        Random number generation function; it accepts an integer N and returns
        a byte string of random data, N bytes long. If not given, a new one is
        instantiated.
    :Returns:
      The PEM block, as a string.

    .. _OpenSSL: http://cvs.openssl.org/fileview?f=openssl/crypto/pem/pem.h&v=1.66.2.1.4.2
    """

    if randfunc is None:
        randfunc = get_random_bytes

    out = "-----BEGIN %s-----\n" % marker
    if passphrase:
        # We only support 3DES for encryption
        salt = randfunc(8)
        key = PBKDF1(passphrase, salt, 16, 1, MD5)
        key += PBKDF1(key + passphrase, salt, 8, 1, MD5)
        objenc = DES3.new(key, DES3.MODE_CBC, salt)
        out += "Proc-Type: 4,ENCRYPTED\nDEK-Info: DES-EDE3-CBC,%s\n\n" %\
            tostr(hexlify(salt).upper())
        # Encrypt with PKCS#7 padding
        data = objenc.encrypt(pad(data, objenc.block_size))

    # Each BASE64 line can take up to 64 characters (=48 bytes of data)
    # b2a_base64 adds a new line character!
    chunks = [tostr(b2a_base64(data[i:i + 48]))
              for i in range(0, len(data), 48)]
    out += "".join(chunks)
    out += "-----END %s-----" % marker
    return out


def decode(pem_data, passphrase=None):
    """Decode a PEM block into binary.

    :Parameters:
      pem_data : string
        The PEM block.
      passphrase : byte string
        If given and the PEM block is encrypted,
        the key will be derived from the passphrase.
    :Returns:
      A tuple with the binary data, the marker string, and a boolean to
      indicate if decryption was performed.
    :Raises ValueError:
      If decoding fails, if the PEM file is encrypted and no passphrase has
      been provided or if the passphrase is incorrect.
    """

    # Verify Pre-Encapsulation Boundary
    r = re.compile("\s*-----BEGIN (.*)-----\n")
    m = r.match(pem_data)
    if not m:
        raise ValueError("Not a valid PEM pre boundary")
    marker = m.group(1)

    # Verify Post-Encapsulation Boundary
    r = re.compile("-----END (.*)-----\s*$")
    m = r.search(pem_data)
    if not m or m.group(1) != marker:
        raise ValueError("Not a valid PEM post boundary")

    # Removes spaces and slit on lines
    lines = pem_data.replace(" ", '').split()

    # Decrypts, if necessary
    if lines[1].startswith('Proc-Type:4,ENCRYPTED'):
        if not passphrase:
            raise ValueError("PEM is encrypted, but no passphrase available")
        DEK = lines[2].split(':')
        if len(DEK) != 2 or DEK[0] != 'DEK-Info':
            raise ValueError("PEM encryption format not supported.")
        algo, salt = DEK[1].split(',')
        salt = unhexlify(tobytes(salt))
        if algo == "DES-CBC":
            # This is EVP_BytesToKey in OpenSSL
            key = PBKDF1(passphrase, salt, 8, 1, MD5)
            objdec = DES.new(key, DES.MODE_CBC, salt)
        elif algo == "DES-EDE3-CBC":
            # Note that EVP_BytesToKey is note exactly the same as PBKDF1
            key = PBKDF1(passphrase, salt, 16, 1, MD5)
            key += PBKDF1(key + passphrase, salt, 8, 1, MD5)
            objdec = DES3.new(key, DES3.MODE_CBC, salt)
        elif algo == "AES-128-CBC":
            key = PBKDF1(passphrase, salt[:8], 16, 1, MD5)
            objdec = AES.new(key, AES.MODE_CBC, salt)
        else:
            raise ValueError("Unsupport PEM encryption algorithm.")
        lines = lines[2:]
    else:
        objdec = None

    # Decode body
    data = a2b_base64(b(''.join(lines[1:-1])))
    enc_flag = False
    if objdec:
        data = unpad(objdec.decrypt(data), objdec.block_size)
        enc_flag = True

    return (data, marker, enc_flag)
