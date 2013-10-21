# -*- coding: utf-8 -*-
#
#  Cipher/mode_gcm.py : GCM AEAD mode
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
Galois/Counter Mode (GCM).
"""

__all__ = [ 'ModeGCM' ]

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *

from binascii import unhexlify, hexlify

from Crypto.Util.py3compat import *

from Crypto.Util import Counter, galois
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.parameters import pop_parameter
from Crypto.Hash.CMAC import _SmoothMAC, MacMismatchError


class _GHASH(_SmoothMAC):
    """GHASH function defined in NIST SP 800-38D, Algorithm 2.

    If X_1, X_2, .. X_m are the blocks of input data, the function
    computes:

       X_1*H^{m} + X_2*H^{m-1} + ... + X_m*H

    in the Galois field GF(2^256) using the reducing polynomial
    (x^128 + x^7 + x^2 + x + 1).
    """

    def __init__(self, hash_subkey, block_size, table_size='64K'):
        _SmoothMAC.__init__(self, block_size, None, 0)
        if table_size == '64K':
            self._hash_subkey = galois._ghash_expand(hash_subkey)
        else:
            self._hash_subkey = hash_subkey
        self._last_y = bchr(0) * 16
        self._mac = galois._ghash

    def copy(self):
        clone = _GHASH(self._hash_subkey, self._bs, table_size='0K')
        _SmoothMAC._deep_copy(self, clone)
        clone._last_y = self._last_y
        return clone

    def _update(self, block_data):
        self._last_y = galois._ghash(block_data, self._last_y,
                                     self._hash_subkey)

    def _digest(self, left_data):
        return self._last_y


class ModeGCM(object):
    """Galois Counter Mode (GCM).

    This is an Authenticated Encryption with Associated Data (`AEAD`_) mode.
    It provides both confidentiality and authenticity.

    The header of the message may be left in the clear, if needed, and it will
    still be subject to authentication. The decryption step tells the receiver
    if the message comes from a source that really knowns the secret key.
    Additionally, decryption detects if any part of the message - including the
    header - has been modified or corrupted.

    This mode requires a *nonce*.

    This mode is only available for ciphers that operate on 128 bits blocks
    (e.g. AES but not TDES).

    See `NIST SP800-38D`_ .

    .. _`NIST SP800-38D`: http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
    .. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
    """

    def __init__(self, factory, key, *args, **kwargs):
        """Create a new block cipher, configured in
        Galois Counter Mode (GCM).

        :Parameters:
          factory : module
            A block cipher module, taken from `Crypto.Cipher`.
            The cipher must have block length of 16 bytes.
            GCM has been only defined for `Crypto.Cipher.AES`.

          key : byte string
            The secret key to use in the symmetric cipher.
            It must be 16 (e.g. *AES-128*), 24 (e.g. *AES-192*)
            or 32 (e.g. *AES-256*) bytes long.

        :Keywords:
          nonce : byte string
            A mandatory value that must never be reused for any other encryption.

            There are no restrictions on its length,
            but it is recommended to use at least 16 bytes.

            The nonce shall never repeat for two
            different messages encrypted with the same key,
            but it does not need to be random.

          mac_len : integer
            Length of the MAC, in bytes.
            It must be no larger than 16 bytes (which is the default).
        """

        self.block_size = factory.block_size

        self._args = list(args)
        self._kwargs = kwargs.copy()
        self._factory = factory
        self._tag = None
        self._key = key

        if self.block_size != 16:
            raise ValueError("GCM mode is only available for ciphers"
                             " that operate on 128 bits blocks")

        # Nonce value
        #import pdb; pdb.set_trace()
        self._nonce = pop_parameter('nonce', 0, self._args, self._kwargs)
        if not self._nonce:
            raise ValueError("MODE_GCM requires a nonce")

        # MAC tag length
        self._mac_len = pop_parameter('mac_len', -1, self._args,
                                      self._kwargs, 16)
        if not (4 <= self._mac_len <= 16):
            raise ValueError("Parameter 'mac_len' must not be larger"
                             " than 16 bytes")

        # Allowed transitions after initialization
        self._next = [self.update, self.encrypt, self.decrypt,
                      self.digest, self.verify]

        self._done_assoc_data = False

        # Length of the ciphertext or plaintext
        self._msg_len = 0

        # Step 1 in SP800-38D, Algorithm 4 (encryption) - Compute H
        # See also Algorithm 5 (decryption)
        hash_subkey = self._new_cipher(key, self._factory.MODE_ECB).encrypt(bchr(0) * 16)

        # Step 2 - Compute J0 (integer, not byte string!)
        if len(self._nonce) == 12:
            self._j0 = bytes_to_long(self._nonce + b("\x00\x00\x00\x01"))
        else:
            fill = (16 - (len(self._nonce) % 16)) % 16 + 8
            ghash_in = (self._nonce +
                        bchr(0) * fill +
                        long_to_bytes(8 * len(self._nonce), 8))
            mac = _GHASH(hash_subkey, factory.block_size, '0K')
            mac.update(ghash_in)
            self._j0 = bytes_to_long(mac.digest())

        # Step 3 - Prepare GCTR cipher for encryption/decryption
        ctr = Counter.new(128, initial_value=self._j0 + 1,
                          allow_wraparound=True)
        self._cipher = self._new_cipher(key, self._factory.MODE_CTR, counter=ctr)

        # Step 5 - Bootstrat GHASH
        self._cipherMAC = _GHASH(hash_subkey, factory.block_size, '64K')

        # Step 6 - Prepare GCTR cipher for GMAC
        ctr = Counter.new(128, initial_value=self._j0, allow_wraparound=True)
        self._tag_cipher = self._new_cipher(key, self._factory.MODE_CTR, counter=ctr)

    def _new_cipher(self, key, mode, **extra_kwargs):
        """Instantiate a new cipher from the factory.

        The cipher is created using the given parameters
        and all parameters that were not consumed when this GCM object
        was created.
        """

        kwargs = self._kwargs.copy()
        kwargs.update(extra_kwargs)
        return self._factory.new(key, mode, *self._args, **kwargs)

    def update(self, assoc_data):
        """Protect associated data

        If there is any associated data, the caller has to invoke
        this function one or more times, before using
        ``decrypt`` or ``encrypt``.

        By *associated data* it is meant any data (e.g. packet headers) that
        will not be encrypted and will be transmitted in the clear.
        However, the receiver is still able to detect any modification to it.
        In GCM, the *associated data* is also called
        *additional authenticated data* (AAD).

        If there is no associated data, this method must not be called.

        The caller may split associated data in segments of any size, and
        invoke this method multiple times, each time with the next segment.

        :Parameters:
          assoc_data : byte string
            A piece of associated data. There are no restrictions on its size.
        """

        if self.update not in self._next:
            raise TypeError("update() can only be called"
                                " immediately after initialization")

        self._next = [self.update, self.encrypt, self.decrypt,
                      self.digest, self.verify]

        return self._cipherMAC.update(assoc_data)

    def encrypt(self, plaintext):
        """Encrypt data with the key and the parameters set at initialization.

        A cipher object is stateful: once you have encrypted a message
        you cannot encrypt (or decrypt) another message using the same
        object.

        The data to encrypt can be broken up in two or
        more pieces and `encrypt` can be called multiple times.

        That is, the statement:

            >>> c.encrypt(a) + c.encrypt(b)

        is equivalent to:

             >>> c.encrypt(a+b)

        This function does not add any padding to the plaintext.

        :Parameters:
          plaintext : byte string
            The piece of data to encrypt.
            It can be of any length.
        :Return:
            the encrypted data, as a byte string.
            It is as long as *plaintext*.
        """

        if self.encrypt not in self._next:
            raise TypeError("encrypt() can only be called after"
                            " initialization or an update()")
        self._next = [self.encrypt, self.digest]

        ct = self._cipher.encrypt(plaintext)

        if not self._done_assoc_data:
            self._cipherMAC.zero_pad()
            self._done_assoc_data = True
        self._cipherMAC.update(ct)
        self._msg_len += len(plaintext)

        return ct

    def decrypt(self, ciphertext):
        """Decrypt data with the key and the parameters set at initialization.

        A cipher object is stateful: once you have decrypted a message
        you cannot decrypt (or encrypt) another message with the same
        object.

        The data to decrypt can be broken up in two or
        more pieces and `decrypt` can be called multiple times.

        That is, the statement:

            >>> c.decrypt(a) + c.decrypt(b)

        is equivalent to:

             >>> c.decrypt(a+b)

        This function does not remove any padding from the plaintext.

        :Parameters:
          ciphertext : byte string
            The piece of data to decrypt.
            It can be of any length.

        :Return: the decrypted data (byte string).
        """

        if self.decrypt not in self._next:
            raise TypeError("decrypt() can only be called"
                            " after initialization or an update()")
        self._next = [self.decrypt, self.verify]

        if not self._done_assoc_data:
            self._cipherMAC.zero_pad()
            self._done_assoc_data = True

        self._cipherMAC.update(ciphertext)
        self._msg_len += len(ciphertext)

        pt = self._cipher.decrypt(ciphertext)

        return pt

    def digest(self):
        """Compute the *binary* MAC tag in an AEAD mode.

        The caller invokes this function at the very end.

        This method returns the MAC that shall be sent to the receiver,
        together with the ciphertext.

        :Return: the MAC, as a byte string.
        """

        if self.digest not in self._next:
            raise TypeError("digest() cannot be called when decrypting"
                                " or validating a message")
        self._next = [self.digest]

        return self._compute_mac()

    def _compute_mac(self):
        """Compute MAC without any FSM checks."""

        if self._tag:
            return self._tag

        # Step 5 in NIST SP 800-38D, Algorithm 4 - Compute S
        self._cipherMAC.zero_pad()
        auth_len = self._cipherMAC.get_len() - self._msg_len
        for tlen in (auth_len, self._msg_len):
            self._cipherMAC.update(long_to_bytes(8 * tlen, 8))
        s_tag = self._cipherMAC.digest()

        # Step 6 - Compute T
        self._tag = self._tag_cipher.encrypt(s_tag)[:self._mac_len]

        return self._tag

    def hexdigest(self):
        """Compute the *printable* MAC tag.

        This method is like `digest`.

        :Return: the MAC, as a hexadecimal string.
        """
        return "".join(["%02x" % bord(x) for x in self.digest()])

    def verify(self, mac_tag):
        """Validate the *binary* MAC tag.

        The caller invokes this function at the very end.

        This method checks if the decrypted message is indeed valid
        (that is, if the key is correct) and it has not been
        tampered with while in transit.

        :Parameters:
          mac_tag : byte string
            This is the *binary* MAC, as received from the sender.
        :Raises MacMismatchError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        if self.verify not in self._next:
            raise TypeError("verify() cannot be called"
                                " when encrypting a message")
        self._next = [self.verify]

        res = 0
        # Constant-time comparison
        for x, y in zip(self._compute_mac(), mac_tag):
            res |= bord(x) ^ bord(y)
        if res or len(mac_tag) != self._mac_len:
            raise MacMismatchError("MAC check failed")

    def hexverify(self, hex_mac_tag):
        """Validate the *printable* MAC tag.

        This method is like `verify`.

        :Parameters:
          hex_mac_tag : string
            This is the *printable* MAC, as received from the sender.
        :Raises MacMismatchError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        self.verify(unhexlify(hex_mac_tag))

    def encrypt_and_digest(self, plaintext):
        """Perform encrypt() and digest() in one step.

        :Parameters:
          plaintext : byte string
            The piece of data to encrypt.
        :Return:
            a tuple with two byte strings:

            - the encrypted data
            - the MAC
        """

        return self.encrypt(plaintext), self.digest()

    def decrypt_and_verify(self, ciphertext, mac_tag):
        """Perform decrypt() and verify() in one step.

        :Parameters:
          ciphertext : byte string
            The piece of data to decrypt.
          mac_tag : byte string
            This is the *binary* MAC, as received from the sender.

        :Return: the decrypted data (byte string).
        :Raises MacMismatchError:
            if the MAC does not match. The message has been tampered with
            or the key is incorrect.
        """

        pt = self.decrypt(ciphertext)
        self.verify(mac_tag)
        return pt
