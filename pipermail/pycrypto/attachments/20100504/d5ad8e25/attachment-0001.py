import cPickle as pickle
import functools
import pickletools
import math
import hashlib
# NOTE: the python random module is *NOT* cryptographically strong!
#       It should be replaced with PyCrypto's Random module.
#       (RandomPool has its own set of problems. see pycrypto.org for more info)
import random

# The raw functions in PyCrypto can be a bit cumbersome from time to time.
# Therefore I wrote some helper functions to provide me with an API which suits
# me better.
from Crypto.Cipher import AES as _block_cipher
from Crypto.PublicKey import RSA as _private_key
get_block_size = lambda : _block_cipher.block_size
get_encrypter = functools.partial(_block_cipher.new,
                                  mode=_block_cipher.MODE_CBC,
                                  IV="1234567890123456"[:get_block_size()])
get_decrypter = get_encrypter
PICKLE_PROTOCOL = 2

def pad(s, block_size=None, pad_char="."):
    if block_size is None:
        block_size = get_block_size()
    return s.ljust(block_size * int(math.ceil(len(s) / float(block_size))), pad_char)

# again: this should be replaced by a cryptographically strong version
def get_random_chars(n=1):
    return "".join(chr(random.getrandbits(8)) for i in xrange(n))

def get_new_block_key(key_size=None):
    if key_size is None:
        key_size = get_block_size()
    return get_random_chars(key_size)

def block_encrypt(message, key):
    encrypter = get_encrypter(key)
    message_pickle = pickle.dumps(message, PICKLE_PROTOCOL)
    return encrypter.encrypt(pad(message_pickle))
    
def block_decrypt(encrypted_message_pickle, key):
    decrypter = get_decrypter(key)
    message_pickle = decrypter.decrypt(encrypted_message_pickle)
    return pickle.loads(message_pickle)

def pubkey_encrypt(message, public_key):
    block_key = get_new_block_key()
    encrypted_message = block_encrypt(message, block_key)
    encrypted_key = public_key.encrypt(block_key, "")
    return (encrypted_key, encrypted_message)

def pubkey_decrypt((encrypted_block_key, encrypted_message), private_key):
    block_key = private_key.decrypt(encrypted_block_key)
    return block_decrypt(encrypted_message, block_key)

def hash_(message):
    msg_pickle = pickle.dumps(message, PICKLE_PROTOCOL)
    # strangly the normal pickle doesn't seem to be unambiguous which
    # in turn causes verification to fail. As a work-around optimizing
    # the pickle seems to remove ambiguities.
    msg_pickle = pickletools.optimize(msg_pickle)
    msg_hash = hashlib.sha1()
    msg_hash.update(msg_pickle)
    return msg_hash.hexdigest()

def sign(msg, private_key):
    return private_key.sign(hash_(msg), "")

def verify(msg, public_key, signature):
    if not public_key.verify(hash_(msg), signature):
        raise RuntimeError("message verification failed!")
    else:
        return True



# a small demonstration
aliceKey = _private_key.generate(1024, get_random_chars)
bobKey = _private_key.generate(1024, get_random_chars)

# alice gives her public key to bob and bob gives his public key to alice
bobPubKey = bobKey.publickey()
alicePubKey = aliceKey.publickey()

# alice wants to share a secret with bob
secret = "I DON'T LIKE SPAM!!!"
# she encrypts it with bobs public key that she received earlier
encryptedSecret = pubkey_encrypt(secret, bobPubKey)
# she signs the messages hash with her own private key
signature = sign(secret, aliceKey)
# then she sends both over to bob
# ...
# ...
# once bob received the stuff he can try decrypting it with his own private key
decryptedSecret = pubkey_decrypt(encryptedSecret, bobKey)
# then he can choose to verify that the message was written by alice by verifying the signature with alice's public key
verify(decryptedSecret, alicePubKey, signature)
print decryptedSecret
# Note that we did not verify that the message was *sent* to bob by alice
# only that it was *written* by alice, and sent to bob by someone who knows
# bob's public key (which is more or less everybody).
