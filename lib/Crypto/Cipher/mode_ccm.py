# -*- coding: utf-8 -*-
#
#  Cipher/mode_ccm.py : CCM AEAD mode
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
Counter with CBC-MAC (CCM) mode.
"""

__all__ = [ 'ModeCCM' ]

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Util.py3compat import *

from binascii import unhexlify, hexlify

from Crypto.Util import Counter
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes, bytes_to_long

from Crypto.Util.parameters import pop_parameter
from Crypto.Hash.CMAC import _SmoothMAC, MacMismatchError


class _CBCMAC(_SmoothMAC):

    def __init__(self, key, ciphermod):
        _SmoothMAC.__init__(self, ciphermod.block_size, None, 0)
        self._key = key
        self._factory = ciphermod

    def ignite(self, data):
        if self._mac:
            raise TypeError("ignite() cannot be called twice")

        self._buffer.insert(0, data)
        self._buffer_len += len(data)
        self._mac = self._factory.new(self._key, self._factory.MODE_CBC, bchr(0) * 16)
        self.update(b(""))

    def _update(self, block_data):
        self._t = self._mac.encrypt(block_data)[-16:]

    def _digest(self, left_data):
        return self._t


class ModeCCM(object):
    """Counter with CBC-MAC (CCM).

    This is an Authenticated Encryption with Associated Data (`AEAD`_) mode.
    It provides both confidentiality and authenticity.

    The header of the message may be left in the clear, if needed, and it will
    still be subject to authentication. The decryption step tells the receiver
    if the message comes from a source that really knowns the secret key.
    Additionally, decryption detects if any part of the message - including the
    header - has been modified or corrupted.

    This mode requires a nonce. The nonce shall never repeat for two
    different messages encrypted with the same key, but it does not need
    to be random.
    Note that there is a trade-off between the size of the nonce and the
    maximum size of a single message you can encrypt.

    It is important to use a large nonce if the key is reused across several
    messages and the nonce is chosen randomly.

    It is acceptable to us a short nonce if the key is only used a few times or
    if the nonce is taken from a counter.

    The following table shows the trade-off when the nonce is chosen at
    random. The column on the left shows how many messages it takes
    for the keystream to repeat **on average**. In practice, you will want to
    stop using the key way before that.

    +--------------------+---------------+-------------------+
    | Avg. # of messages |    nonce      |     Max. message  |
    | before keystream   |    size       |     size          |
    | repeats            |    (bytes)    |     (bytes)       |
    +====================+===============+===================+
    |       2**52        |      13       |        64K        |
    +--------------------+---------------+-------------------+
    |       2**48        |      12       |        16M        |
    +--------------------+---------------+-------------------+
    |       2**44        |      11       |         4G        |
    +--------------------+---------------+-------------------+
    |       2**40        |      10       |         1T        |
    +--------------------+---------------+-------------------+
    |       2**36        |       9       |        64P        |
    +--------------------+---------------+-------------------+
    |       2**32        |       8       |        16E        |
    +--------------------+---------------+-------------------+

    This mode is only available for ciphers that operate on 128 bits blocks
    (e.g. AES but not TDES).

    See `NIST SP800-38C`_ or RFC3610_ .

    .. _`NIST SP800-38C`: http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C.pdf
    .. _RFC3610: https://tools.ietf.org/html/rfc3610
    .. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
    """

    def __init__(self, factory, key, *args, **kwargs):
        """Create a new block cipher, configured in CCM mode.

        :Parameters:
          factory : module
            A cryptographic algorithm module from `Crypto.Cipher`.
          key : byte string
            The secret key to use in the symmetric cipher.

        :Keywords:
          nonce : byte string
            A mandatory value that must never be reused for any other encryption.

            Its length must be in the range ``[7..13]``.
            11 or 12 bytes are reasonable values in general. Bear in
            mind that with CCM there is a trade-off between nonce length and
            maximum message size.

          mac_len : integer
            Length of the MAC, in bytes. It must be even and in
            the range ``[4..16]``. The default is 16.

          msg_len : integer
            Length of the message to (de)cipher.
            If not specified, ``encrypt`` or ``decrypt`` may only be called once.

          assoc_len : integer
            Length of the associated data.
            If not specified, all data is internally buffered.
        """

        #: The block size of the underlying cipher, in bytes.
        self.block_size = factory.block_size

        self._args = list(args)
        self._kwargs = kwargs.copy()
        self._factory = factory
        self._tag = None
        self._key = key

        if self.block_size != 16:
            raise ValueError("CCM mode is only available for ciphers"
                             " that operate on 128 bits blocks")

        # MAC tag length
        self._mac_len = pop_parameter('mac_len', -1, self._args,
                                      self._kwargs, 16) # t
        if self._mac_len not in (4, 6, 8, 10, 12, 14, 16):
            raise ValueError("Parameter 'mac_len' must be even"
                             " and in the range 4..16")

        # Nonce value
        self._nonce = pop_parameter('nonce', 0, self._args, self._kwargs) # N
        if not (self._nonce and 7 <= len(self._nonce) <= 13):
            raise ValueError("Length of parameter 'nonce' must be"
                             " in the range 7..13 bytes")

        self._msg_len = pop_parameter('msg_len', -1, self._args, self._kwargs) # p
        self._assoc_len = pop_parameter('assoc_len', -1, self._args, self._kwargs) # a

        self._cipherMAC = _CBCMAC(key, factory)
        self._done_assoc_data = False      # True when all associated data
                                           # has been processed

        # Allowed transitions after initialization
        self._next = [self.update, self.encrypt, self.decrypt,
                      self.digest, self.verify]

        # Try to start CCM
        self._start_ccm()

    def _start_ccm(self, assoc_len=None, msg_len=None):
        # CCM mode. This method creates the 2 ciphers used for the MAC
        # (self._cipherMAC) and for the encryption/decryption (self._cipher).
        #
        # Member _assoc_buffer may already contain user data that needs to be
        # authenticated.

        if self._cipherMAC.can_reduce():
            # Already started
            return
        if assoc_len is not None:
            self._assoc_len = assoc_len
        if msg_len is not None:
            self._msg_len = msg_len
        if None in (self._assoc_len, self._msg_len):
            return

        # q is the length of Q, the encoding of the message length
        q = 15 - len(self._nonce)

        ## Compute B_0
        flags = (
                64 * (self._assoc_len > 0) +
                8 * divmod(self._mac_len - 2, 2)[0] +
                (q - 1)
                )
        b_0 = bchr(flags) + self._nonce + long_to_bytes(self._msg_len, q)

        # Start CBC MAC with zero IV
        assoc_len_encoded = b('')
        if self._assoc_len > 0:
            if self._assoc_len < (2 ** 16 - 2 ** 8):
                enc_size = 2
            elif self._assoc_len < (2L ** 32):
                assoc_len_encoded = b('\xFF\xFE')
                enc_size = 4
            else:
                assoc_len_encoded = b('\xFF\xFF')
                enc_size = 8
            assoc_len_encoded += long_to_bytes(self._assoc_len, enc_size)
        self._cipherMAC.ignite(b_0 + assoc_len_encoded)

        # Start CTR cipher
        prefix = bchr(q - 1) + self._nonce
        ctr = Counter.new(128 - len(prefix) * 8, prefix, initial_value=0)
        self._cipher = self._new_cipher(self._key, self._factory.MODE_CTR, counter=ctr)
        # Will XOR against CBC MAC
        self._s_0 = self._cipher.encrypt(bchr(0) * 16)

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
        In CCM, the *associated data* is also called
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
        """Encrypt data with the key set at initialization.

        A cipher object is stateful: once you have encrypted a message
        you cannot encrypt (or decrypt) another message using the same
        object.

        This method can be called only **once** if ``msg_len`` was
        not passed at initialization.

        If ``msg_len`` was given, the data to encrypt can be broken
        up in two or more pieces and `encrypt` can be called
        multiple times.

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

        if self._assoc_len is None:
            self._start_ccm(assoc_len=self._cipherMAC.get_len())
        if self._msg_len is None:
            self._start_ccm(msg_len=len(plaintext))
            self._next = [self.digest]
        if not self._done_assoc_data:
            self._cipherMAC.zero_pad()
            self._done_assoc_data = True

        self._cipherMAC.update(plaintext)
        return self._cipher.encrypt(plaintext)

    def decrypt(self, ciphertext):
        """Decrypt data with the key set at initialization.

        A cipher object is stateful: once you have decrypted a message
        you cannot decrypt (or encrypt) another message with the same
        object.

        This method can be called only **once** if ``msg_len`` was
        not passed at initialization.

        If ``msg_len`` was given, the data to decrypt can be
        broken up in two or more pieces and `decrypt` can be
        called multiple times.

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

        if self._assoc_len is None:
            self._start_ccm(assoc_len=self._cipherMAC.get_len())
        if self._msg_len is None:
            self._start_ccm(msg_len=len(ciphertext))
            self._next = [self.verify]
        if not self._done_assoc_data:
            self._cipherMAC.zero_pad()
            self._done_assoc_data = True

        pt = self._cipher.decrypt(ciphertext)
        self._cipherMAC.update(pt)
        return pt

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

        if self._assoc_len is None:
            self._start_ccm(assoc_len=self._cipherMAC.get_len())
        if self._msg_len is None:
            self._start_ccm(msg_len=0)
        self._cipherMAC.zero_pad()
        self._tag = strxor(self._cipherMAC.digest(),
                           self._s_0)[:self._mac_len]

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
