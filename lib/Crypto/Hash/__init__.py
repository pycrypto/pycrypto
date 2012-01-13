# -*- coding: utf-8 -*-
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

"""Hashing algorithms

Hash functions take arbitrary strings as input, and produce an output
of fixed size that is dependent on the input; it should never be
possible to derive the input data given only the hash function's
output.  Hash functions can be used simply as a checksum, or, in
association with a public-key algorithm, can be used to implement
digital signatures.

The hashing modules here all support the interface described in PEP
247, "API for Cryptographic Hash Functions".

Submodules:

Crypto.Hash.HMAC
 RFC 2104. Keyed-Hashing for Message Authentication.
Crypto.Hash.MD2
 RFC1319. Rivest's Message Digest algorithm, with a 128 bit digest. This algorithm is both slow and insecure.
Crypto.Hash.MD4
 RFC1320. Rivest's Message Digest algorithm, with a 128 bit digest. This algorithm is insecure.
Crypto.Hash.MD5
 RFC1321. Rivest's Message Digest algorithm, with a 128 bit digest. This algorithm is insecure.
Crypto.Hash.RIPEMD
 RACE Integrity Primitives Evaluation Message Digest algorithm, with a 160 bit digest.
Crypto.Hash.SHA
 Secure Hash Algorithm 1 (SHA-1), with a 160 bit digest. Published in FIPS PUB 180-1/2/3.
Crypto.Hash.SHA224
 Secure Hash Algorithm 2 (SHA-2 family), with a 224 bit digest. Published in FIPS PUB 180-2/3.
Crypto.Hash.SHA256
 Secure Hash Algorithm 2 (SHA-2 family), with a 256 bit digest. Published in FIPS PUB 180-2/3.
Crypto.Hash.SHA384
 Secure Hash Algorithm 2 (SHA-2 family), with a 384 bit digest. Published in FIPS PUB 180-2/3.
Crypto.Hash.SHA512
 Secure Hash Algorithm 2 (SHA-2 family), with a 512 bit digest. Published in FIPS PUB 180-2/3.

"""

__all__ = ['HMAC', 'MD2', 'MD4', 'MD5', 'RIPEMD', 'SHA',
           'SHA224', 'SHA256', 'SHA384', 'SHA512']
__revision__ = "$Id$"


