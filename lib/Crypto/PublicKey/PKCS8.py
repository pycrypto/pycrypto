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
Module for encoding and decoding private keys according to `PKCS#8`_.

.. _`PKCS#8`: http://www.ietf.org/rfc/rfc5208.txt

"""
from Crypto.Util.asn1 import *

def _isInt(x, onlyNonNegative=False):
    test = 0
    try:
        test += x
    except TypeError:
        return False
    return not onlyNonNegative or x>=0

def decode(key):
    """Decode a PKCS#8 key into a private key
    
    :Parameters:
      key : byte string
        The private key encoded according to PKCS#8
    :Return:
      A tuple containing the key algorithm identifier (OID, dotted string),
      the private key (DER object, byte string), and the parameters
      (either None or a DER object, byte string).
    :Raises ValueError:
      If decoding fails
    """

    #
    #   PrivateKeyInfo ::= SEQUENCE {
    #       version                 Version,
    #       privateKeyAlgorithm     PrivateKeyAlgorithmIdentifier,
    #       privateKey              PrivateKey,
    #       attributes              [0]  IMPLICIT
    #       Attributes OPTIONAL
    #   }
    #
    pkInfo = DerSequence()
    pkInfo.decode(key)
    if not 3 <= len(pkInfo) <= 4:
        raise ValueError("Not a valid PrivateKeyInfo SEQUENCE")
    # Version, must be 0
    if not _isInt(pkInfo[0]) or pkInfo[0]!=0:
        raise ValueError("Not a valid PrivateKeyInfo SEQUENCE")
    #
    #   AlgorithmIdentifier  ::=  SEQUENCE  {
    #       algorithm               OBJECT IDENTIFIER,
    #       parameters              ANY DEFINED BY algorithm OPTIONAL
    #   }
    #
    algoId = DerSequence()
    algoId.decode(pkInfo[1])
    if not 1 <= len(algoId) <= 2:
        raise ValueError("Not a valid AlgorithmIdentifier SEQUENCE")
    algo = DerObjectId()
    algo.decode(algoId[0])
    params = None
    if len(algoId)==2:
        params = algoId[1]
    # PrivateKey ::= OCTET STRING
    privateKey = DerOctetString()
    privateKey.decode(pkInfo[2])
    return (algo.value, privateKey.payload, params)

def encode(algo_oid, privateKey, params=DerNull()):
    """Encode a private key into PKCS#8 format.

    :Parameters:
      algo_oid : string
        The object identifier (OID), as a dotted string
      privateKey : byte string
        The private key encoded in DER
      params : DER object or None
        The algorithm parameters
    :Return:
      The private key encoded according to PKCS#8
    """
    pkInfo = DerSequence()
    pkInfo.append(0)
    algoId = DerSequence()
    algoId.append(DerObjectId(algo_oid).encode())
    algoId.append(params.encode())
    pkInfo.append(algoId.encode())
    pkInfo.append(DerOctetString(privateKey).encode())
    return pkInfo.encode()

