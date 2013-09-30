# -*- coding: utf-8 -*-
#
#  Cipher/mode_eax.py : EAX AEAD mode
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
EAX mode.
"""

__all__ = [ 'ModeEAX' ]

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *

from binascii import unhexlify, hexlify

from Crypto.Util.py3compat import *

from Crypto.Util import Counter
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes, bytes_to_long

from Crypto.Util.parameters import pop_parameter
from Crypto.Hash.CMAC import MacMismatchError
from Crypto.Hash import CMAC


class ModeEAX(object):
    """*EAX* mode.

    This is an Authenticated Encryption with Associated Data
    (`AEAD`_) mode. It provides both confidentiality and authenticity.

    The header of the message may be left in the clear, if needed,
    and it will still be subject to authentication.

    The decryption step tells the receiver if the message comes
    from a source that really knowns the secret key.
    Additionally, decryption detects if any part of the message -
    including the header - has been modified or corrupted.

    This mode requires a *nonce*.

    This mode is only available for ciphers that operate on 64 or
    128 bits blocks.

    There are no official standards defining EAX.
    The implementation is based on `a proposal`__ that
    was presented to NIST.

    .. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
    .. __: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/eax/eax-spec.pdf
    """

    def __init__(self, factory, key, *args, **kwargs):
        """Create a new block cipher, configured in EAX mode.

        :Parameters:
          factory : module
            A cryptographic algorithm module from `Crypto.Cipher`.

          key : byte string
            The secret key to use in the symmetric cipher.

        :Keywords:
          nonce : byte string
            A mandatory value that must never be reused for any other encryption.
            There are no restrictions on its length,
            but it is recommended to use at least 16 bytes.

            The nonce shall never repeat for two
            different messages encrypted with the same key,
            but it does not need to be random.

          mac_len : integer
            Length of the MAC, in bytes. It must be no
            larger than the cipher block bytes (which is the default).
        """

        self.block_size = factory.block_size

        self._args = list(args)
        self._kwargs = kwargs.copy()
        self._factory = factory
        self._tag = None
        self._key = key

        # Nonce value
        self._nonce = pop_parameter('nonce', 0, self._args, self._kwargs)
        if not self._nonce:
            raise ValueError("MODE_EAX requires a nonce")

        # Allowed transitions after initialization
        self._next = [self.update, self.encrypt, self.decrypt,
                      self.digest, self.verify]

        # MAC tag length
        self._mac_len = pop_parameter('mac_len', -1, self._args,
                                      self._kwargs, self.block_size)
        if not (self._mac_len and 4 <= self._mac_len <= self.block_size):
            raise ValueError("Parameter 'mac_len' must not be larger than %d"
                             % self.block_size)

        self._omac = [
                CMAC.new(key, bchr(0) * (self.block_size - 1) + bchr(i),
                         ciphermod=factory)
                for i in xrange(0, 3)
                ]

        # Compute MAC of nonce
        self._omac[0].update(self._nonce)

        self._cipherMAC = self._omac[1]

        # MAC of the nonce is also the initial counter for CTR encryption
        counter_int = bytes_to_long(self._omac[0].digest())
        counter_obj = Counter.new(
                        self.block_size * 8,
                        initial_value=counter_int,
                        allow_wraparound=True)
        self._cipher = self._new_cipher(key, self._factory.MODE_CTR,
                                        counter=counter_obj)

    def _new_cipher(self, key, mode, **extra_kwargs):
        """Instantiate a new cipher from the factory.

        The cipher is created using the given parameters
        and all parameters that were not consumed when this CCM object
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
        self._omac[2].update(ct)
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
        self._omac[2].update(ciphertext)
        return self._cipher.decrypt(ciphertext)

    def digest(self):
        """Compute the *binary* MAC tag.

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

        tag = bchr(0) * self.block_size
        for i in xrange(3):
            tag = strxor(tag, self._omac[i].digest())
        self._tag = tag[:self._mac_len]

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
