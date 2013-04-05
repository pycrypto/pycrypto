# -*- coding: utf-8 -*-
#
# DH.py - Diffie-Hellman key exchange
# (also called Diffie-Hellman-Merkle)
#
# Written by Elizabeth Myers, 4 Apr 2013
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

from Crypto.Random.random import randint
from Crypto.Util.number import bytes_to_long, long_to_bytes

"""This is a Python implementation of the Diffie-Hellman key exchange protocol.

Diffie-Hellman is an algorithm by which two parties can agree on a shared secret
key, known only to them. The secret is negotiated over an insecure network
without the two parties ever passing the actual shared secret, or their private
keys, between them.

More information can be found in PKCS #3 (Diffie-Hellman Key Agreement
Standard):
    http://www.rsasecurity.com/rsalabs/pkcs/pkcs-3/
"""

# I am aware this is ugly but it's a big number. :(
def_p = int('0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67'
            'CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF2'
            '5F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6'
            'F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007C'
            'B8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62'
            'F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32'
            '905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'
            'DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC4'
            '2DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D06'
            '0C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261A'
            'D2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE11757'
            '7A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D1'
            '20A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A94'
            '6834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA628'
            '7C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AF'
            'B81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C0'
            '8F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA'
            '37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B086'
            '5A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151'
            '2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7'
            'CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A9'
            '7A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814'
            'CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0'
            'EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860'
            'EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF', 0)
def_g = 2

class DHError(Exception): pass

class DiffieHellman(object):
    def __init__(self, p=None, g=None, priv_key=None):
        """Initialise DH object

        :Parameters:
            p : integer or long
                prime number for DH key exchange. Should be a large "safe prime"
                (a prime of the form 2*p+1, where p is also prime)
            g : integer
                generator for DH key exchange. g should be a prime number. It
                need not be large (2, 3, 5 are common choices).
            priv_key : integer, long, or bytes
                the private key to use. Should be generated from a secure RNG.
                it should be in the range of p > priv_key > 1
        """
        if p is not None and g is not None:
            self.p = p
            self.g = g
        else:
            logging.debug('Using default prime and generator');
            self.p = def_p
            self.g = def_g

        self.priv_key = priv_key


    def generateKeys(self):
        """Generate the private and public keys.

        :Return:
            The generated public key based on g**p % p; send this to the other
            party.
        """
        if not self.priv_key:
            self.priv_key = randint(1, self.p - 1)
        
        priv_key = self.priv_key
        if isinstance(priv_key, bytes):
            # Convert for our purposes
            priv_key = bytes_to_long(self.priv_key)

        self.pub_key = pow(self.g, self.priv_key, self.p)
        return long_to_bytes(self.pub_key)


    """Compute the shared secret

    :Parameters:
        rpub_key : integer, long, or bytes
            remote public key
    :Return:
        The shared secret, derived from rpub_key**priv_key % p
    """
    def computeKey(self, rpub_key):
        if not self.priv_key:
            raise DHError('Private key not generated')

        if isinstance(rpub_key, bytes):
            rpub_key = bytes_to_long(rpub_key)

        return long_to_bytes(pow(rpub_key, self.priv_key, self.p))

