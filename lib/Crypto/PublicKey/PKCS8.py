# -*- coding: utf-8 -*-
#
#  PublicKey/PKCS8.py : PKCS#8 functions
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
"""
Module for handling private keys wrapped according to `PKCS#8`_.

PKCS8 is a standard for storing private key information.
The wrapped key can either be clear or encrypted.

All encryption algorithms are based on passphrase-based key derivation.
The following mechanisms are fully supported:

* *PBKDF2WithHMAC-SHA1AndAES128-CBC*
* *PBKDF2WithHMAC-SHA1AndAES192-CBC*
* *PBKDF2WithHMAC-SHA1AndAES256-CBC*
* *PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC*

The following mechanisms are only supported for importing keys.
They are much weaker than the ones listed above, and they are provided
for backward compatibility only:

* *pbeWithMD5AndRC2-CBC*
* *pbeWithMD5AndDES-CBC*
* *pbeWithSHA1AndRC2-CBC*
* *pbeWithSHA1AndDES-CBC*

.. _`PKCS#8`: http://www.ietf.org/rfc/rfc5208.txt

"""

import sys

if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Util.py3compat import *

from Crypto import Random
from Crypto.Util.asn1 import *

from Crypto.Cipher import DES3, DES, ARC2, AES
from Crypto.Hash import MD5, SHA as SHA1
from Crypto.Protocol.KDF import PBKDF2, PBKDF1

__all__ = [ 'wrap', 'unwrap', 'unpad' ]

def _isInt(x):
    test = 0
    try:
        test += x
    except TypeError:
        return False
    return True

def decode_der(obj_class, binstr):
    """Instantiate a DER object class, decode a DER binary string in it, and
    return the object."""
    der = obj_class()
    der.decode(binstr)
    return der

rsadsi = "1.2.840.113549"
pkcs_5 = rsadsi + ".1.5"
encryptionAlgorithm = rsadsi + ".3"
id_PBKDF2 = pkcs_5 + ".12"
id_PBES2  = pkcs_5 + ".13"
id_DES_EDE3_CBC = encryptionAlgorithm + ".7"
id_PBE_MD5_DES_CBC = pkcs_5 + ".3"
id_PBE_SHA1_RC2_CBC = pkcs_5 + ".11"
id_PBE_MD5_RC2_CBC = pkcs_5 + ".6"
id_PBE_SHA1_DES_CBC = pkcs_5 + ".10"
id_AES = "2.16.840.1.101.3.4.1"
id_AES128_CBC = id_AES + ".2"
id_AES192_CBC = id_AES + ".22"
id_AES256_CBC = id_AES + ".42"

def unpad(padded_data, block_size):
    """Remove PKCS#7-style padding."""

    padding_len = bord(padded_data[-1])
    if padding_len<1 or padding_len>block_size or\
        padded_data[-padding_len:]!=bchr(padding_len)*padding_len:
            raise ValueError("Padding is incorrect.")
    return padded_data[:-padding_len]

class _DES_CBC(object):
    """Cipher based on DES in CBC mode with PKCS#7 padding.
    
    Given the limited security of DES, this class only provides decryption for
    backward compatibility reasons.
    """
    
    key_size = 8
    iv_size = 8

    def __init__(self, iv):
        self._iv = iv

    def decrypt(self, ct, key):
        cipher = DES.new( key, DES.MODE_CBC, self._iv)
        pt_padded = cipher.decrypt(ct)
        return unpad(pt_padded, cipher.block_size)

class _RC2_CBC(object):
    """Cipher based on RC2/64 in CBC mode with PKCS#7 padding.
    
    Given the limited security of RC2/64, this class only provides decryption for
    backward compatibility reasons.
    """
    
    key_size = 8
    iv_size = 8

    def __init__(self, iv):
        self._iv = iv

    def decrypt(self, ct, key):
        cipher = ARC2.new( key, ARC2.MODE_CBC, self._iv, effective_keylen=64)
        pt_padded = cipher.decrypt(ct)
        return unpad(pt_padded, cipher.block_size)

class _DES_EDE3_CBC(object):
    """Cipher based on TDES in CBC mode with PKCS#7 padding"""

    key_size = 24
    iv_size = 8

    def __init__(self, iv):
        self._iv = iv

    def get_algorithm_id(self):
        #
        # AlgorithmIdentifier  ::=  SEQUENCE  {
        #       algorithm   OBJECT IDENTIFIER,
        #       parameters  ANY DEFINED BY algorithm OPTIONAL
        # }
        #
        # SupportingAlgorithms ALGORITHM-IDENTIFIER ::=
        #   {OCTET STRING (SIZE(8)) IDENTIFIED BY des-EDE3-CBC}
        #
        algo_id = newDerSequence (
                DerObjectId(id_DES_EDE3_CBC),
                DerOctetString(self._iv)
                )
        return algo_id
 
    def encrypt(self, pt, key):
        cipher = DES3.new(key, DES3.MODE_CBC, self._iv)
        padding = cipher.block_size-len(pt)%cipher.block_size
        ct = cipher.encrypt(pt+bchr(padding)*padding)
        return ct

    def decrypt(self, ct, key):
        cipher = DES3.new( key, DES3.MODE_CBC, self._iv)
        pt_padded = cipher.decrypt(ct)
        return unpad(pt_padded, cipher.block_size)

class _AES_CBC(object):
    """Base class for AES ciphers based in CBC mode with PKCS#7 padding"""

    iv_size = 16

    def __init__(self, iv):
        self._iv = iv

    def get_algorithm_id(self):
        algo_id = newDerSequence (
                DerObjectId(self._oid),
                DerOctetString(self._iv)
                )
        return algo_id
 
    def encrypt(self, pt, key):
        cipher = AES.new( key, AES.MODE_CBC, self._iv)
        padding = cipher.block_size-len(pt)%cipher.block_size
        ct = cipher.encrypt(pt+bchr(padding)*padding)
        return ct

    def decrypt(self, ct, key):
        cipher = AES.new( key, AES.MODE_CBC, self._iv)
        pt_padded = cipher.decrypt(ct)
        return unpad(pt_padded, cipher.block_size)

class _AES128_CBC(_AES_CBC):
    """Cipher based on AES128 in CBC mode with PKCS#7 padding"""

    key_size = 16

    def __init__(self, iv):
        _AES_CBC.__init__(self, iv)
        self._oid = id_AES128_CBC

class _AES192_CBC(_AES_CBC):
    """Cipher based on AES192 in CBC mode with PKCS#7 padding"""

    key_size = 24

    def __init__(self, iv):
        self._iv = iv
        self._oid = id_AES192_CBC

class _AES256_CBC(_AES_CBC):
    """Cipher based on AES192 in CBC mode with PKCS#7 padding"""

    key_size = 32

    def __init__(self, iv):
        self._iv = iv
        self._oid = id_AES256_CBC

class _DES_EDE3_CBC_Factory(object):
    """Factory for _DES_EDE3_CBC objects"""

    def generate(self, algo_params, randfunc):
        iv = randfunc(8)
        return _DES_EDE3_CBC(iv)

    def decode(params):
        iv = decode_der(DerOctetString, params).payload
        return _DES_EDE3_CBC(iv)
    decode = staticmethod(decode)

class _AES128_CBC_Factory(object):
    """Factory for _AES128_CBC objects"""

    def generate(self, algo_params, randfunc):
        iv = randfunc(16)
        return _AES128_CBC(iv)

    def decode(params):
        iv = decode_der(DerOctetString, params).payload
        return _AES128_CBC(iv)
    decode = staticmethod(decode)

class _AES192_CBC_Factory(object):
    """Factory for _AES128_CBC objects"""

    def generate(self, algo_params, randfunc):
        iv = randfunc(16)
        return _AES192_CBC(iv)

    def decode(params):
        iv = decode_der(DerOctetString, params).payload
        return _AES192_CBC(iv)
    decode = staticmethod(decode)

class _AES256_CBC_Factory(object):
    """Factory for _AES256_CBC objects"""

    def generate(self, algo_params, randfunc):
        iv = randfunc(16)
        return _AES256_CBC(iv)

    def decode(params):
        iv = decode_der(DerOctetString, params).payload
        return _AES256_CBC(iv)
    decode = staticmethod(decode)

class _PBKDF1(object):
    """Deprecated key derivation function defined in PKCS#5 v1.5."""

    def __init__(self, salt, count, hashAlgo):
        self._salt = salt
        self._count = count
        self._hashAlgo = hashAlgo

    def derive(self, passphrase, key_size):
        return PBKDF1(passphrase, self._salt, key_size, self._count,
                self._hashAlgo)

class _PBKDF2(object):
    """Key derivation function from passwords (defined in PKCS#5 v2.0)."""

    def __init__(self, salt, count):
        self._salt = salt
        self._count = count

    def get_algorithm_id(self):
        #
        # AlgorithmIdentifier  ::=  SEQUENCE  {
        #       algorithm   OBJECT IDENTIFIER,
        #       parameters  ANY DEFINED BY algorithm OPTIONAL
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
        algo_oid = newDerSequence(
                    DerObjectId(id_PBKDF2),
                    newDerSequence(
                        DerOctetString(self._salt),
                        DerInteger(self._count)
                        )
                    )
        return algo_oid

    def derive(self, passphrase, key_size):
        return PBKDF2(passphrase, self._salt, key_size, self._count)

class _PBKDF2_Factory(object):
    """Factory for _PBKDF2 objects"""

    def generate(self, algo_params, randfunc):
        salt = randfunc(algo_params.get("salt_size", 8))
        count = algo_params.get("iteration_count", 1000)
        return _PBKDF2(salt, count)

    def decode(params):
        pbkdf2_params = decode_der(DerSequence, params)
        salt = decode_der(DerOctetString, pbkdf2_params[0]).payload
        count = pbkdf2_params[1]
        return _PBKDF2(salt, count)
    decode = staticmethod(decode)

class _PBES1(object):
    """Deprecated encryption scheme with password-based key derivation
    (defined in PKCS#5 v1.5)."""

    def __init__(self, pbkdf1, cipher):
        self._pbkdf1 = pbkdf1
        self._cipher = cipher

    def decrypt(self, passphrase, ct):
        key_size = self._cipher.key_size
        iv_size = self._cipher.iv_size
        d = self._pbkdf1.derive(passphrase, iv_size+key_size)
        key,iv = d[:key_size], d[key_size:]
        pt = self._cipher(iv).decrypt(ct, key)
        return pt

class _PBES2(object):
    """Encryption scheme with password-based key derivation
    (defined in PKCS#5 v2.0)."""

    def __init__(self, kdf, cipher):
        self._kdf = kdf
        self._cipher = cipher

    def get_algorithm_id(self):
        #
        # AlgorithmIdentifier  ::=  SEQUENCE  {
        #       algorithm   OBJECT IDENTIFIER,
        #       parameters  ANY DEFINED BY algorithm OPTIONAL
        # }
        #
        # PBES2-params ::= SEQUENCE {
        #       keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
        #       encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
        # }
        #
        algo_id = newDerSequence(
                DerObjectId(id_PBES2),
                newDerSequence(
                        self._kdf.get_algorithm_id(),
                        self._cipher.get_algorithm_id(),
                    )
                )
        return algo_id

    def encrypt(self, passphrase, pt):
        key = self._kdf.derive(passphrase, self._cipher.key_size)
        ct = self._cipher.encrypt(pt, key)
        return ct

    def decrypt(self, passphrase, ct):
        key = self._kdf.derive(passphrase, self._cipher.key_size)
        pt = self._cipher.decrypt(ct, key)
        return pt

#
# Dictionary mapping a cipher OID to a cipher factory
#
cipher_dic = {
        id_DES_EDE3_CBC : _DES_EDE3_CBC_Factory,
        id_AES128_CBC   : _AES128_CBC_Factory,
        id_AES192_CBC   : _AES192_CBC_Factory,
        id_AES256_CBC   : _AES256_CBC_Factory
        }

#
# Dictionary mapping a key derivation function (KDF) OID to a KDF factory
#
kdf_dict = { id_PBKDF2 : _PBKDF2_Factory }

class _PBES2_Factory(object):
    """Factory for _PBES2 objects"""

    def __init__(self, kdf_factory, cipher_factory):
        self._kdf_factory = kdf_factory
        self._cipher_factory = cipher_factory

    def generate(self, algo_params, randfunc):
        cipher = self._cipher_factory.generate(algo_params, randfunc)
        kdf = self._kdf_factory.generate(algo_params, randfunc)
        return _PBES2(kdf, cipher)

    def decode(params):
        #
        # PBES2-params ::= SEQUENCE {
        #       keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
        #       encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
        # }
        #
        pbes2_params = decode_der(DerSequence, params)
        keyDerivationFunc = decode_der(DerSequence, pbes2_params[0])
        keyDerivationOid = decode_der(DerObjectId, keyDerivationFunc[0]).value
    
        encryptionScheme = decode_der(DerSequence, pbes2_params[1])
        encryptionOid = decode_der(DerObjectId, encryptionScheme[0]).value
        
        cipher_factory = cipher_dic[encryptionOid]
        cipher = cipher_factory.decode(encryptionScheme[1])

        kdf_factory = kdf_dict[keyDerivationOid]
        kdf = kdf_factory.decode(keyDerivationFunc[1])

        return _PBES2(kdf, cipher)
    decode = staticmethod(decode)

class _PBES1_Factory(object):
    """Factory for _PBES1 objects"""

    def __init__(self, hashAlgo, cipherAlgo):
        self._hashAlgo = hashAlgo
        self._cipherAlgo = cipherAlgo

    def decode(self, params):
        #
        # PBEParameter ::= SEQUENCE {
        #   salt OCTET STRING (SIZE(8)),
        #   iterationCount INTEGER
        # }
        #
        pbes_params = decode_der(DerSequence, params)
        salt = decode_der(DerOctetString, pbes_params[0]).payload
        iterations = pbes_params[1]
        kdf = _PBKDF1(salt, iterations, self._hashAlgo)
        return _PBES1(kdf, self._cipherAlgo)

#
# Dictionary mapping an OID to a password-based decryption scheme.
#
enc_dict = {
        id_PBES2 : _PBES2_Factory,
        id_PBE_MD5_DES_CBC : _PBES1_Factory(MD5, _DES_CBC),
        id_PBE_SHA1_RC2_CBC : _PBES1_Factory(SHA1, _RC2_CBC),
        id_PBE_MD5_RC2_CBC : _PBES1_Factory(MD5, _RC2_CBC),
        id_PBE_SHA1_DES_CBC : _PBES1_Factory(SHA1, _DES_CBC)
        }

#
# Dictionary mapping a PKCS#8 encryption scheme to a scheme factory
#
# The generic pattern for a scheme string is:
#
# <kdf>With<digest>And<cipher>
#

algos = {
        'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC' :
            _PBES2_Factory(_PBKDF2_Factory(), _DES_EDE3_CBC_Factory()),
        'PBKDF2WithHMAC-SHA1AndAES128-CBC' :
            _PBES2_Factory(_PBKDF2_Factory(), _AES128_CBC_Factory()),
        'PBKDF2WithHMAC-SHA1AndAES192-CBC' :
            _PBES2_Factory(_PBKDF2_Factory(), _AES192_CBC_Factory()),
        'PBKDF2WithHMAC-SHA1AndAES256-CBC' :
            _PBES2_Factory(_PBKDF2_Factory(), _AES256_CBC_Factory())
        }

def wrap(private_key, key_oid, passphrase=b(''), wrap_algo=None,
        wrap_params=None, key_params=None, randfunc=None):
    """Wrap a private key into a PKCS#8 blob (clear or encrypted).

    :Parameters:

      private_key : byte string
        The private key encoded in binary form. The actual encoding is
        algorithm specific. In most cases, it is DER.

      key_oid : string
        The object identifier (OID) of the private key to wrap.
        It is a dotted string, like "`1.2.840.113549.1.1.1`".

      passphrase : binary string
        The secret passphrase from which the wrapping key is derived.
        If no encryption is required, the value `None` has to be passed.

      wrap_algo : string
        The identifier of the wrapping algorithm to use. The default value is
        '`PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC`'.

      wrap_params : dictionary 
        Parameters to use for wrapping. They are specific to the wrapping
        algorithm.

        +------------------+-----------------------------------------------+
        | Key              | Description                                   |
        +==================+===============================================+
        | iteration_count  | The KDF algorithm is repeated several times to|
        |                  | slow down brute force attacks on passwords.   |
        |                  | The default value is 1000.                    |
        +------------------+-----------------------------------------------+
        | salt_size        | Salt is used to thwart dictionary and rainbow |
        |                  | attacks on passwords. The default value is 8  |
        |                  | bytes.                                        |
        +------------------+-----------------------------------------------+

      key_params : DER object
        The algorithm parameters associated to the private key, if any is required.

      randfunc : callable
        Random number generation function; it should accept a single integer N and
        return a string of random data, N bytes long.
        If not specified, a new RNG will be instantiated from ``Crypto.Random``.

    :Return:
      The PKCS#8-wrapped private key (possibly encrypted), as a binary string.
    """

    if key_params is None:
        key_params = DerNull()

    #
    #   PrivateKeyInfo ::= SEQUENCE {
    #       version                 Version,
    #       privateKeyAlgorithm     PrivateKeyAlgorithmIdentifier,
    #       privateKey              PrivateKey,
    #       attributes              [0]  IMPLICIT Attributes OPTIONAL
    #   }
    #
    pk_info = newDerSequence(
            0,
            newDerSequence(
                DerObjectId(key_oid),
                key_params
                ),
            newDerOctetString(private_key)
            )
    pk_info_der = pk_info.encode()

    if passphrase is None:
        return pk_info_der

    if len(passphrase) == 0:
        raise ValueError("The PKCS#8 passphrase cannot be empty.")

    #
    # EncryptedPrivateKeyInfo ::= SEQUENCE {
    #   encryptionAlgorithm  EncryptionAlgorithmIdentifier,
    #   encryptedData        EncryptedData
    # }
    #
    # EncryptedData ::= OCTET STRING
    #

    if wrap_algo is None:
        wrap_algo = 'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC'
    if wrap_params is None:
        wrap_params = {}
    if randfunc is None:
        randfunc = Random.new().read
    enc_obj = algos[wrap_algo].generate(wrap_params, randfunc)
    encPkInfo = newDerSequence(
            enc_obj.get_algorithm_id(),
            newDerOctetString(enc_obj.encrypt(passphrase, pk_info_der))
            )

    return encPkInfo.encode()

def unwrap(p8_private_key, passphrase=None):
    """Unwrap a private key from a PKCS#8 blob (clear or encrypted).
    
    :Parameters:
      p8_private_key : byte string
        The private key wrapped into a PKCS#8 blob
      passphrase : byte string
        The passphrase to use to decrypt the blob (if it is encrypted).
    :Return:
      A tuple containing:

      #. the algorithm identifier of the wrapped key (OID, dotted string)
      #. the private key (byte string, DER encoded)
      #. the associated parameters (byte string, DER encoded) or None

    :Raises ValueError:
      If decoding fails
    """

    if passphrase:
        #
        # EncryptedPrivateKeyInfo ::= SEQUENCE {
        #   encryptionAlgorithm  EncryptionAlgorithmIdentifier,
        #   encryptedData        EncryptedData
        # }
        #
        encPkInfo = decode_der(DerSequence, p8_private_key)
        encAlgo = decode_der(DerSequence, encPkInfo[0])
        ciphertext = decode_der(DerOctetString, encPkInfo[1]).payload
        
        #
        #   AlgorithmIdentifier  ::=  SEQUENCE  {
        #       algorithm               OBJECT IDENTIFIER,
        #       parameters              ANY DEFINED BY algorithm OPTIONAL
        #   }
        #
        algo = decode_der(DerObjectId, encAlgo[0]).value

        try:
            decobj = enc_dict[algo].decode(encAlgo[1])
        except KeyError, e:
            raise ValueError("Unsupported PKCS#5 Object ID " + str(e))
        p8_private_key = decobj.decrypt(passphrase, ciphertext)

    #
    #   PrivateKeyInfo ::= SEQUENCE {
    #       version                 Version,
    #       privateKeyAlgorithm     PrivateKeyAlgorithmIdentifier,
    #       privateKey              PrivateKey,
    #       attributes              [0]  IMPLICIT Attributes OPTIONAL
    #   }
    #
    pk_info = decode_der(DerSequence, p8_private_key)
    if len(pk_info) == 2 and not passphrase:
        raise ValueError("Not a valid clear PKCS#8 structure (maybe it is encrypted?)")
    if not 3 <= len(pk_info) <= 4 or pk_info[0]!=0:
        raise ValueError("Not a valid PrivateKeyInfo SEQUENCE")
    #
    #   AlgorithmIdentifier  ::=  SEQUENCE  {
    #       algorithm               OBJECT IDENTIFIER,
    #       parameters              ANY DEFINED BY algorithm OPTIONAL
    #   }
    #
    algo_id = decode_der(DerSequence, pk_info[1])
    if not 1 <= len(algo_id) <= 2:
        raise ValueError("Not a valid AlgorithmIdentifier SEQUENCE")
    algo = decode_der(DerObjectId, algo_id[0]).value
    privateKey = decode_der(DerOctetString, pk_info[2]).payload
    if len(algo_id)==2 and algo_id[1]!=b('\x05\x00'):
        params = algo_id[1]
    else:
        params = None
    return (algo, privateKey, params)


