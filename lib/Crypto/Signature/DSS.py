# -*- coding: utf-8 -*-
#
#  Signature/DSS.py : DSS.py
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
Digital Signature Standard (DSS), as specified in `FIPS PUB 186`__.

A sender signs a message in the following way:

        >>> from Crypto.Hash import SHA256
        >>> from Crypto.PublicKey import DSA
        >>> from Crypto.Signature import DSS
        >>>
        >>> message = b'I give my permission to order #4355'
        >>> key = DSA.importKey(open('privkey.der').read())
        >>> h = SHA256.new(message)
        >>> signer = DSS.new(key, 'fips-186-3')
        >>> signature = signer.sign(h)

The receiver can verify authenticity of the message:

        >>> key = DSA.importKey(open('pubkey.der').read())
        >>> h = SHA256.new(received_message)
        >>> verifier = DSS.new(key, 'fips-186-3')
        >>> if verifier.verify(h, signature):
        >>>    print "The signature is authentic."
        >>> else:
        >>>    print "The signature is not authentic."

.. __: http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf

"""

__all__ = ['new', 'DSS_SigScheme']

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Util.py3compat import *

from Crypto import Random
from Crypto.Random.random import StrongRandom
from Crypto.Util.asn1 import DerSequence
from Crypto.Util.number import size as bit_size, long_to_bytes, bytes_to_long

from Crypto.Hash import HMAC


class DSS_SigScheme(object):
    """This signature scheme can perform DSS signature or verification."""

    #: List of L (bit length of p) and N (bit length of q) combinations
    #: that are allowed by FIPS 186-3.
    fips_186_3_ln = ((1024, 160), (2048, 224), (2048, 256), (3072, 256))

    def __init__(self, key, mode, encoding='binary', randfunc=None):
        """Initialize this Digital Signature Standard object.

        :Parameters:
          key : a DSA key object
            If the key has the private half, both signature and
            verification are possible.
            If it only has the public half, verification is possible
            but not signature generation.

            Let *L* and *N* be the bit lengths of the modules *p* and *q*.

            If mode is *'fips-186-3'*,
            the combination *(L,N)* must apper in the following list,
            in compliance to section 4.2 of `FIPS-186`__:

            - (1024, 160)
            - (2048, 224)
            - (2048, 256)
            - (3072, 256)

            Note that the FIPS specification also defines how the key
            must be generated. PyCrypto does not generate DSA keys
            in a FIPS compliant way.

          mode : string
            The parameter can take these values:

            - *'fips-186-3'*. The signature generation is carried out
              according to `FIPS-186`__: the nonce *k* is taken from the RNG.
            - *'deterministic-rfc6979'*. The signature generation
              process does not rely on a random generator.
              See RFC6979_.

          encoding : string
            How the signature is encoded. This value determines the output of
            ``sign`` and the input of ``verify``.

            The following values are accepted:

            - *'binary'*, the signature is the raw concatenation
              of *r* and *s*. The size in bytes of the signature is always
              two times the size of *q*.

            - *'der'*, the signature is a DER encoded SEQUENCE with two
              INTEGERs, *r* and *s*. The size of the signature is variable.

          randfunc : callable
            The source of randomness. If `None`, the internal RNG is used.
            It is not used under mode *'deterministic-rfc6979'*.

        .. __: http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
        .. __: http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
        .. _RFC6979: http://tools.ietf.org/html/rfc6979
        """

        # The goal of the 'mode' parameter is to avoid to
        # have the current version of the standard as default.
        #
        # Over time, such version will be superseded by (for instance)
        # FIPS 186-4 and it will be odd to have -3 as default.

        self._deterministic = False
        if mode == 'deterministic-rfc6979':
            self._deterministic = True
        elif mode not in ('fips-186-3', ):
            raise ValueError("Unknown DSS mode '%s'" % mode)

        if encoding not in ('binary', 'der'):
            raise ValueError("Unknown encoding '%s'" % encoding)

        if randfunc is None:
            randfunc = Random.get_random_bytes

        self._encoding = encoding
        self._randfunc = randfunc

        # Verify that lengths of p and q are standard compliant
        self._l, self._n = [(bit_size(x) + 7) >> 3 for x in (key.p, key.q)]
        if not self._deterministic:
            if (self._l * 8, self._n * 8) not in self.fips_186_3_ln:
                raise ValueError("L/N (%d, %d) is not compliant"
                                 " to FIPS 186-3" %
                                 (self._l, self._n))
        self._key = key

    def can_sign(self):
        """Return True if this signature object can be used
        for signing messages."""

        return self._key.has_private()

    def _bits2int(self, bstr):
        """See 2.3.2 in RFC6979"""

        result = bytes_to_long(bstr)
        q_len = bit_size(self._key.q)
        b_len = len(bstr) * 8
        if b_len > q_len:
            result >>= (b_len - q_len)
        return result

    def _int2octets(self, int_mod_q):
        """See 2.3.3 in RFC6979"""

        if not (0 < int_mod_q < self._key.q):
            raise ValueError("Wrong input to int2octets()")
        return long_to_bytes(int_mod_q, self._n)

    def _bits2octets(self, bstr):
        """See 2.3.4 in RFC6979"""

        z1 = self._bits2int(bstr)
        if z1 < self._key.q:
            z2 = z1
        else:
            z2 = z1 - self._key.q
        return self._int2octets(z2)

    def _compute_nonce(self, mhash):
        """Generate k in a deterministic way"""

        # See section 3.2 in RFC6979.txt
        # Step a
        h1 = mhash.digest()
        # Step b
        mask_v = bchr(1) * mhash.digest_size
        # Step c
        nonce_k = bchr(0) * mhash.digest_size

        for int_oct in 0, 1:
            # Step d/f
            nonce_k = HMAC.new(nonce_k,
                               mask_v + bchr(int_oct) +
                               self._int2octets(self._key.x) +
                               self._bits2octets(h1), mhash).digest()
            # Step e/g
            mask_v = HMAC.new(nonce_k, mask_v, mhash).digest()

        nonce = -1
        while not (0 < nonce < self._key.q):
            # Step h.C (second part)
            if nonce != -1:
                nonce_k = HMAC.new(nonce_k, mask_v + bchr(0),
                                   mhash).digest()
                mask_v = HMAC.new(nonce_k, mask_v, mhash).digest()

            # Step h.A
            mask_t = b("")

            # Step h.B
            while len(mask_t) < self._n:
                mask_v = HMAC.new(nonce_k, mask_v, mhash).digest()
                mask_t += mask_v

            # Step h.C (first part)
            nonce = self._bits2int(mask_t)
        return nonce

    def sign(self, mhash):
        """Produce the DSS signature of a message.

        :Parameters:
          mhash : hash object
            The hash that was carried out over the message.
            The object belongs to the `Crypto.Hash` package.

            Under mode *'fips-186-3'*, the hash must be a FIPS
            approved secure hash (SHA-1 or a member of the SHA-2 family).

        :Return: The signature encoded as a byte string.
        :Raise ValueError:
            If the hash algorithm is incompatible to the DSA key.
        :Raise TypeError:
            If the DSA key has no private half.
        """

        # Generate the nonce k (critical!)
        if self._deterministic:
            nonce = self._compute_nonce(mhash)
        else:
            if self._n > mhash.digest_size * 8:
                raise ValueError("Hash is not long enough")

            if not mhash.name.upper().startswith("SHA"):
                raise ValueError("Hash %s does not belong to SHS" % mhash.name)

            rng = StrongRandom(randfunc=self._randfunc)
            nonce = rng.randint(1, self._key.q - 1)

        # Perform signature using the crippled API
        z = mhash.digest()[:self._n]
        sig_pair = self._key.sign(z, nonce)

        # Encode the signature into a single byte string
        if self._encoding == 'binary':
            output = b("").join([long_to_bytes(x, self._n)
                                 for x in sig_pair])
        else:
            # Dss-sig  ::=  SEQUENCE  {
            #               r       OCTET STRING,
            #               s       OCTET STRING
            # }
            der_seq = DerSequence(sig_pair)
            output = der_seq.encode()

        return output

    def verify(self, mhash, signature):
        """Verify that a certain DSS signature is authentic.

        This function checks if the party holding the private half of the key
        really signed the message.

        :Parameters:
          mhash : hash object
            The hash that was carried out over the message.
            This is an object belonging to the `Crypto.Hash` module.


            Under mode *'fips-186-3'*, the hash must be a FIPS
            approved secure hash (SHA-1 or a member of the SHA-2 family).

          signature : byte string
            The signature that needs to be validated.

        :Return: True if verification is correct. False otherwise.
        """

        if not self._deterministic:
            if self._n > mhash.digest_size * 8:
                raise ValueError("Hash is not long enough")
            if not mhash.name.lower().startswith("sha"):
                raise ValueError("Hash %s does not belong to SHS" % mhash.name)

        if self._encoding == 'binary':
            if len(signature) != (2 * self._n):
                return False
            r_prime, s_prime = [bytes_to_long(x)
                                for x in (signature[:self._n],
                                          signature[self._n:])]
        else:
            try:
                der_seq = DerSequence()
                der_seq.decode(signature)
            except (ValueError, IndexError):
                return False
            if len(der_seq) != 2 or not der_seq.hasOnlyInts():
                return False
            r_prime, s_prime = der_seq[0], der_seq[1]

        if not (0 < r_prime < self._key.q) or not (0 < s_prime < self._key.q):
            return False

        z = mhash.digest()[:self._n]
        result = self._key.verify(z, (r_prime, s_prime))
        return result


def new(key, mode, encoding='binary', randfunc=None):
    """Return a signature scheme object `DSS_SigScheme` that
    can be used to perform DSS signature or verification.

    :Parameters:
      key : a DSA key object
        If the key has got its private half, both signature and
        verification are possible.

        If it only has the public half, verification is possible
        but not signature generation.

        If *L* and *N* are the bit lengths of the modules *p* and *q*,
        the combination *(L,N)* must appear in the following list,
        in compliance to section 4.2 of `FIPS-186`__:

        - (1024, 160)
        - (2048, 224)
        - (2048, 256)
        - (3072, 256)

      mode : string
        The parameter can take these values:

        - *'fips-186-3'*. The signature generation is carried out
          according to `FIPS-186`__: the nonce *k* is taken from the RNG.
        - *'deterministic-rfc6979'*. The signature generation
          process does not rely on a random generator.
          See RFC6979_.

      encoding : string
        How the signature is encoded. This value determines the output of
        ``sign`` and the input of ``verify``.

        The following values are accepted:

        - *'binary'*, the signature is the raw concatenation
          of *r* and *s*. The size in bytes of the signature is always
          two times the size of *q*.

        - *'der'*, the signature is a DER encoded SEQUENCE with two
          INTEGERs, *r* and *s*. The size of the signature is variable.

      randfunc : callable
        The source of randomness. If ``None``, the internal RNG is used.
        It is not used under mode *'deterministic-rfc6979'*.

    .. __: http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
    .. __: http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
    .. _RFC6979: http://tools.ietf.org/html/rfc6979
    """

    return DSS_SigScheme(key, mode, encoding, randfunc)
