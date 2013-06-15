#
#  PublicKey/_PBES.py : Password-Based Encryption functions
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

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Util.py3compat import *

from Crypto import Random
from Crypto.Util.asn1 import *

from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import MD5, SHA1
from Crypto.Cipher import DES, ARC2, DES3, AES
from Crypto.Protocol.KDF import PBKDF1, PBKDF2

# These are the ASN.1 definitions used by the PBES1/2 logic:
#
# EncryptedPrivateKeyInfo ::= SEQUENCE {
#   encryptionAlgorithm  EncryptionAlgorithmIdentifier,
#   encryptedData        EncryptedData
# }
#
# EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
#
# EncryptedData ::= OCTET STRING
#
# AlgorithmIdentifier  ::=  SEQUENCE  {
#       algorithm   OBJECT IDENTIFIER,
#       parameters  ANY DEFINED BY algorithm OPTIONAL
# }
#
# PBEParameter ::= SEQUENCE {
#       salt OCTET STRING (SIZE(8)),
#       iterationCount INTEGER
# }
# 
# PBES2-params ::= SEQUENCE {
#       keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
#       encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
# }
#
# PBKDF2-params ::= SEQUENCE {
#   salt CHOICE {
#       specified OCTET STRING,
#       otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
#       },
#   iterationCount INTEGER (1..MAX),
#   keyLength INTEGER (1..MAX) OPTIONAL,
#   prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1
#   }
#

def decode_der(obj_class, binstr):
    """Instantiate a DER object class, decode a DER binary string in it, and
    return the object."""
    der = obj_class()
    der.decode(binstr)
    return der

class PBES1(object):
    """Deprecated encryption scheme with password-based key derivation
    (originally defined in PKCS#5 v1.5, but still present in `v2.0`__).
    
    .. __: http://www.ietf.org/rfc/rfc2898.txt
    """

    def decrypt(data, passphrase):
        """Decrypt a piece of data using a passphrase and *PBES1*.

        The algorithm to use is automatically detected.

        :Parameters:
          data : byte string
            The piece of data to decrypt.
          passphrase : byte string
            The passphrase to use for decrypting the data.
        :Returns:
          The decrypted data, as a binary string.
        """

        encryptedPrivateKeyInfo = decode_der(DerSequence, data)
        encryptedAlgorithm = decode_der(DerSequence, encryptedPrivateKeyInfo[0])
        encryptedData = decode_der(DerOctetString,
                encryptedPrivateKeyInfo[1]).payload

        pbe_oid = decode_der(DerObjectId, encryptedAlgorithm[0]).value
        cipher_params = {}
        if pbe_oid == "1.2.840.113549.1.5.3":
            # PBE_MD5_DES_CBC
            hashmod = MD5
            ciphermod = DES
        elif pbe_oid == "1.2.840.113549.1.5.6":
            # PBE_MD5_RC2_CBC
            hashmod = MD5
            ciphermod = ARC2
            cipher_params['effective_keylen'] = 64
        elif pbe_oid == "1.2.840.113549.1.5.10":
            # PBE_SHA1_DES_CBC
            hashmod = SHA1
            ciphermod = DES
        elif pbe_oid == "1.2.840.113549.1.5.11":
            # PBE_SHA1_RC2_CBC
            hashmod = SHA1
            ciphermod = ARC2
            cipher_params['effective_keylen'] = 64
        else:
            raise ValueError("Unknown OID")

        pbe_params = decode_der(DerSequence, encryptedAlgorithm[1])
        salt = decode_der(DerOctetString, pbe_params[0]).payload
        iterations = pbe_params[1]

        key_iv = PBKDF1(passphrase, salt, 16, iterations, hashmod)
        key, iv = key_iv[:8], key_iv[8:]

        cipher = ciphermod.new(key, ciphermod.MODE_CBC, iv, **cipher_params)
        pt = cipher.decrypt(encryptedData)
        return unpad(pt, cipher.block_size)
    decrypt = staticmethod(decrypt)
 
class PBES2(object):
    """Encryption scheme with password-based key derivation
    (defined in `PKCS#5 v2.0`__).

    .. __: http://www.ietf.org/rfc/rfc2898.txt."""

    def encrypt(data, passphrase, mode, algo_params=None, randfunc=None):
        """Encrypt a piece of data using a passphrase and *PBES2*.

        :Parameters:
          data : byte string
            The piece of data to encrypt.
          passphrase : byte string
            The passphrase to use for encrypting the data.
          mode : string
            The identifier of the encryption algorithm to use.
            The default value is '``PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC``'.
          algo_params : dictionary 
            Parameters to use for wrapping. They are specific to the wrapping
            algorithm.

            +------------------+-----------------------------------------------+
            | Key              | Description                                   |
            +==================+===============================================+
            | iteration_count  | The KDF algorithm is repeated several times to|
            |                  | slow down brute force attacks on passwords.   |
            |                  | The default value is 1 000.                   |
            +------------------+-----------------------------------------------+
            | salt_size        | Salt is used to thwart dictionary and rainbow |
            |                  | attacks on passwords. The default value is 8  |
            |                  | bytes.                                        |
            +------------------+-----------------------------------------------+

          randfunc : callable
            Random number generation function; it should accept a single integer N and
            return a string of random data, N bytes long.
            If not specified, a new RNG will be instantiated from ``Crypto.Random``.

        :Returns:
          The encrypted data, as a binary string.
        """

        if algo_params is None:
            algo_params = {}
 
        if randfunc is None:
            randfunc = Random.new().read

        if mode == 'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC':
            key_size = 24
            module = DES3
            mode = DES3.MODE_CBC
            enc_oid = "1.2.840.113549.3.7"
        elif mode == 'PBKDF2WithHMAC-SHA1AndAES128-CBC':
            key_size = 16
            module = AES
            mode = AES.MODE_CBC
            enc_oid = "2.16.840.1.101.3.4.1.2"
        elif mode == 'PBKDF2WithHMAC-SHA1AndAES192-CBC':
            key_size = 24
            module = AES
            mode = AES.MODE_CBC
            enc_oid = "2.16.840.1.101.3.4.1.22"
        elif mode == 'PBKDF2WithHMAC-SHA1AndAES256-CBC':
            key_size = 32
            module = AES
            mode = AES.MODE_CBC
            enc_oid = "2.16.840.1.101.3.4.1.42"
        else:
            raise ValueError("Unknown mode")

        # Get random data
        IV = randfunc(module.block_size)
        salt = randfunc(algo_params.get("salt_size", 8))

        # Derive key from password
        count = algo_params.get("iteration_count", 1000)
        key = PBKDF2(passphrase, salt, key_size, count)
        keyDerivationFunc = newDerSequence(
                DerObjectId("1.2.840.113549.1.5.12"),   # PBKDF2
                newDerSequence(
                    DerOctetString(salt),
                    DerInteger(count)
                )
        )
       
        # Create cipher and use it
        cipher = module.new(key, mode, IV)
        encryptedData = cipher.encrypt(pad(data, cipher.block_size))
        encryptionScheme = newDerSequence(
                DerObjectId(enc_oid),
                DerOctetString(IV)
        )

        # Result
        encryptedPrivateKeyInfo = newDerSequence(
            # encryptionAlgorithm
            newDerSequence(
                DerObjectId("1.2.840.113549.1.5.13"),   # PBES2
                newDerSequence(
                    keyDerivationFunc,
                    encryptionScheme
                ),
            ),
            DerOctetString(encryptedData)
        )
        return encryptedPrivateKeyInfo.encode()
    encrypt = staticmethod(encrypt)
 
    def decrypt(data, passphrase):
        """Decrypt a piece of data using a passphrase and *PBES2*.

        The algorithm to use is automatically detected.

        :Parameters:
          data : byte string
            The piece of data to decrypt.
          passphrase : byte string
            The passphrase to use for decrypting the data.
        :Returns:
          The decrypted data, as a binary string.
        """

        encryptedPrivateKeyInfo = decode_der(DerSequence, data)
        encryptionAlgorithm = decode_der(DerSequence, encryptedPrivateKeyInfo[0])
        encryptedData = decode_der(DerOctetString,
                encryptedPrivateKeyInfo[1]).payload

        pbe_oid = decode_der(DerObjectId, encryptionAlgorithm[0]).value
        if pbe_oid != "1.2.840.113549.1.5.13":
            raise ValueError("Not a PBES2 object")

        pbes2_params = decode_der(DerSequence, encryptionAlgorithm[1])
       
        ### Key Derivation Function selection
        keyDerivationFunc = decode_der(DerSequence, pbes2_params[0])
        keyDerivation_oid = decode_der(DerObjectId, keyDerivationFunc[0]).value
    
        # For now, we only support PBKDF2
        if keyDerivation_oid != "1.2.840.113549.1.5.12":
            raise ValueError("Unknown KDF")
        
        pbkdf2_params = decode_der(DerSequence, keyDerivationFunc[1])
        salt = decode_der(DerOctetString, pbkdf2_params[0]).payload
        iteration_count = pbkdf2_params[1]
        if len(pbkdf2_params)>2:
            pbkdf2_key_length = pbkdf2_params[2]
        else:
            pbkdf2_key_length = None
        if len(pbkdf2_params)>3:
            raise ValueError("Unsupported PRF for PBKDF2")

        ### Cipher selection
        encryptionScheme = decode_der(DerSequence, pbes2_params[1])
        encryption_oid = decode_der(DerObjectId, encryptionScheme[0]).value

        if encryption_oid == "1.2.840.113549.3.7":
            # DES_EDE3_CBC
            ciphermod = DES3
            key_size = 24
        elif encryption_oid == "2.16.840.1.101.3.4.1.2":
            # AES128_CBC
            ciphermod = AES
            key_size = 16
        elif encryption_oid == "2.16.840.1.101.3.4.1.22":
            # AES192_CBC
            ciphermod = AES
            key_size = 24
        elif encryption_oid == "2.16.840.1.101.3.4.1.42":
            # AES256_CBC
            ciphermod = AES
            key_size = 32
        else:
            raise ValueError("Unsupported cipher")
       
        if pbkdf2_key_length and pbkdf2_key_length!=key_size:
            raise ValueError("Mismatch between PBKDF2 parameters and selected cipher")

        IV = decode_der(DerOctetString, encryptionScheme[1]).payload

        # Create cipher
        key = PBKDF2(passphrase, salt, key_size, iteration_count)
        cipher = ciphermod.new(key, ciphermod.MODE_CBC, IV)

        # Decrypt data
        pt = cipher.decrypt(encryptedData)
        return unpad(pt, cipher.block_size)
    decrypt = staticmethod(decrypt)


