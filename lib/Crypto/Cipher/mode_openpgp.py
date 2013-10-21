# -*- coding: utf-8 -*-
#
#  Cipher/_mode_openpgp.py : OPENPGP mode
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
OpenPGP mode.

"""

__all__ = [ 'ModeOpenPGP' ]

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *

from binascii import unhexlify, hexlify

from Crypto.Util.py3compat import *

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.parameters import pop_parameter


class ModeOpenPGP(object):
    """OpenPGP mode.

    This mode is a variant of CFB, and it is only used in PGP and
    OpenPGP_ applications.

    An Initialization Vector (*IV*) is required.

    Unlike CFB, the *encrypted* IV (not the IV itself) is
    transmitted to the receiver.

    The IV is a random data block. Two of its bytes are duplicated to act
    as a checksum for the correctness of the key. The encrypted IV is
    therefore 2 bytes longer than the clean IV.

    .. _OpenPGP: http://tools.ietf.org/html/rfc4880
    """

    def __init__(self, factory, key, *args, **kwargs):
        """Create a new block cipher, configured in OpenPGP mode.

        :Parameters:
          factory : module
            The module.
          key : byte string
            The secret key to use in the symmetric cipher.

        :Keywords:
          IV : byte string
            The initialization vector to use for encryption or decryption.

            For encryption, the IV must be as long as the
            cipher block size.

            For decryption, it must be 2 bytes longer (it is actually
            the *encrypted* IV which was prefixed to the ciphertext).
        """

        #: The block size of the underlying cipher, in bytes.
        self.block_size = factory.block_size

        self._args = list(args)
        self._kwargs = kwargs.copy()
        self._factory = factory

        # A few members are specifically created for this mode:
        #  - _encrypted_iv, set in this constructor
        #  - _done_first_block, set to True after the first encryption
        #  - _done_last_block, set to True after a partial block is processed
        self._done_first_block = False
        self._done_last_block = False

        #: The Initialization Vector originally used to create the object.
        #: The value does not change.
        self.IV = pop_parameter('iv', 0, self._args, self._kwargs)
        if self.IV is None:
            self.IV = pop_parameter('IV', 0, self._args, self._kwargs)
        if not self.IV:
            raise ValueError("MODE_OPENPGP requires an IV")

        # Instantiate a temporary cipher to process the IV
        IV_cipher = self._new_cipher(
                        key,
                        self._factory.MODE_CFB,
                        IV=bchr(0) * self.block_size,
                        segment_size=self.block_size * 8)

        # The cipher will be used for...
        if len(self.IV) == self.block_size:
            # ... encryption
            self._encrypted_IV = IV_cipher.encrypt(
                    self.IV + self.IV[-2:] +            # Plaintext
                    bchr(0) * (self.block_size - 2)     # Padding
                    )[:self.block_size + 2]
        elif len(self.IV) == self.block_size + 2:
            # ... decryption
            self._encrypted_IV = self.IV
            self.IV = IV_cipher.decrypt(
                        self.IV +                           # Ciphertext
                        bchr(0) * (self.block_size - 2)     # Padding
                        )[:self.block_size + 2]
            if self.IV[-2:] != self.IV[-4:-2]:
                raise ValueError("Failed integrity check for OPENPGP IV")
            self.IV = self.IV[:-2]
        else:
            raise ValueError("Length of IV must be %d or %d bytes"
                             " for MODE_OPENPGP"
                             % (self.block_size, self.block_size + 2))

        # Instantiate the cipher for the real PGP data
        self._cipher = self._new_cipher(
                            key,
                            self._factory.MODE_CFB,
                            IV=self._encrypted_IV[-self.block_size:],
                            segment_size=self.block_size * 8
                            )

    def _new_cipher(self, key, mode, **extra_kwargs):
        """Instantiate a new cipher from the factory.

        The cipher is created using the given parameters
        and all parameters that were not consumed when this CCM object
        was created.
        """

        kwargs = self._kwargs.copy()
        kwargs.update(extra_kwargs)
        return self._factory.new(key, mode, *self._args, **kwargs)

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
            It must be a multiple of *block_size*,
            unless it is the last chunk of the message.

        :Return:
            the encrypted data, as a byte string.
            It is as long as *plaintext* with one exception:
            when encrypting the first message chunk,
            the encypted IV is prepended to the returned ciphertext.
        """

        padding_length = (
                            (self.block_size - len(plaintext)
                                % self.block_size)
                        % self.block_size
                        )
        if padding_length > 0:
            # CFB mode requires ciphertext to have length multiple
            # of block size,
            # but PGP mode allows the last block to be shorter
            if self._done_last_block:
                 raise ValueError(
                         "Only the last chunk is allowed to have"
                        " length not multiple of %d bytes",
                        self.block_size
                        )
            self._done_last_block = True
            padded = plaintext + bchr(0) * padding_length
            res = self._cipher.encrypt(padded)[:len(plaintext)]
        else:
             res = self._cipher.encrypt(plaintext)
        if not self._done_first_block:
            res = self._encrypted_IV + res
            self._done_first_block = True
        return res

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
            It must be a multiple of *block_size*,
            unless it is the last chunk of the message.

        :Return: the decrypted data (byte string).
        """

        padding_length = ((self.block_size -
                         len(ciphertext) % self.block_size)
                         % self.block_size)
        if padding_length > 0:
            # CFB mode requires ciphertext to have length multiple
            # of block size,
            # but PGP mode allows the last block to be shorter
            if self._done_last_block:
                raise ValueError(
                        "Only the last chunk is allowed to have"
                        " length not multiple of %d bytes",
                        self.block_size
                        )
            self._done_last_block = True
            padded = ciphertext + bchr(0) * padding_length
            res = self._cipher.decrypt(padded)[:len(ciphertext)]
        else:
            res = self._cipher.decrypt(ciphertext)
        return res

