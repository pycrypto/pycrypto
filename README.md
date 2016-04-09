Python Cryptography Toolkit (pycrypto)
======================================

This is a collection of both secure hash functions (such as SHA256 and
RIPEMD160), and various encryption algorithms (AES, DES, RSA, ElGamal,
etc.).  The package is structured to make adding new modules easy.
This section is essentially complete, and the software interface will
almost certainly not change in an incompatible way in the future; all
that remains to be done is to fix any bugs that show up.  If you
encounter a bug, please report it in the GitHub issue tracker at

       https://github.com/dlitz/pycrypto/issues

An example usage of the SHA256 module is:

>>> from Crypto.Hash import SHA256
>>> hash = SHA256.new()
>>> hash.update('message')
>>> hash.digest()
'\xabS\n\x13\xe4Y\x14\x98+y\xf9\xb7\xe3\xfb\xa9\x94\xcf\xd1\xf3\xfb"\xf7\x1c\xea\x1a\xfb\xf0+F\x0cm\x1d'

An example usage of an encryption algorithm (AES, in this case) is:

>>> from Crypto.Cipher import AES
>>> obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
>>> message = "The answer is no"
>>> ciphertext = obj.encrypt(message)
>>> ciphertext
'\xd6\x83\x8dd!VT\x92\xaa`A\x05\xe0\x9b\x8b\xf1'
>>> obj2 = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
>>> obj2.decrypt(ciphertext)
'The answer is no'

One possible application of the modules is writing secure
administration tools.  Another application is in writing daemons and
servers.  Clients and servers can encrypt the data being exchanged and
mutually authenticate themselves; daemons can encrypt private data for
added security.  Python also provides a pleasant framework for
prototyping and experimentation with cryptographic algorithms; thanks
to its arbitrary-length integers, public key algorithms are easily
implemented.

As of PyCrypto 2.1.0, PyCrypto provides an easy-to-use random number
generator:

>>> from Crypto import Random
>>> rndfile = Random.new()
>>> rndfile.read(16)
'\xf7.\x838{\x85\xa0\xd3>#}\xc6\xc2jJU'

A stronger version of Python's standard "random" module is also
provided:

>>> from Crypto.Random import random
>>> random.choice(['dogs', 'cats', 'bears'])
'bears'

Caveat: For the random number generator to work correctly, you must
call Random.atfork() in both the parent and child processes after
using os.fork()


Installation
============

PyCrypto is written and tested using Python version 2.1 through 3.3.  Python
1.5.2 is not supported.

The modules are packaged using the Distutils, so you can simply run
"python setup.py build" to build the package, and "python setup.py
install" to install it.

Linux installation requires the Python developer tools to be installed. These
can be found in the ``python-dev`` package on Debian/Ubuntu and the 
``python2-devel`` package on Red Hat/Fedora. If you are using a non-standard
Python version for your distribution, you may require a different package.
Consult your package manager's documentation for instructions on how to
install these packages. Other distributions may have different package names.

To verify that everything is in order, run "python setup.py test".  It
will test all the cryptographic modules, skipping ones that aren't
available.  If the test script reports an error on your machine,
please report the bug using the bug tracker (URL given above).  If
possible, track down the bug and include a patch that fixes it,
provided that you are able to meet the eligibility requirements at
http://www.pycrypto.org/submission-requirements/.

It is possible to test a single sub-package or a single module only, for instance
when you investigate why certain tests fail and don't want to run the whole
suite each time. Use "python setup.py test --module=name", where 'name'
is either a sub-package (Cipher, PublicKey, etc) or a module (Cipher.DES,
PublicKey.RSA, etc).
To further cut test coverage, pass also the option "--skip-slow-tests".

To install the package under the site-packages directory of
your Python installation, run "python setup.py install".

If you have any comments, corrections, or improvements for this
package, please report them to our mailing list, accessible via the
PyCrypto website:

    http://www.pycrypto.org/
    https://www.dlitz.net/software/pycrypto/

