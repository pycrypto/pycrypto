# -*- coding: utf-8 -*-
#
#  SelfTest/Hash/common.py: Common code for Crypto.SelfTest.Hash
#
# Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
# and in 2013 by Fabrizio Tarizzo <fabrizio@fabriziotarizzo.org>
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

"""Self-testing for PyCrypto hash modules"""

__revision__ = "$Id$"

import sys
import unittest
import binascii
import Crypto.Hash
from Crypto.Util.py3compat import *
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *

# For compatibility with Python 2.1 and Python 2.2
if sys.hexversion < 0x02030000:
    # Python 2.1 doesn't have a dict() function
    # Python 2.2 dict() function raises TypeError if you do dict(MD5='blah')
    def dict(**kwargs):
        return kwargs.copy()
else:
    dict = dict


class HashDigestSizeSelfTest(unittest.TestCase):
    
    def __init__(self, hashmod, description, expected):
        unittest.TestCase.__init__(self)
        self.hashmod = hashmod
        self.expected = expected
        self.description = description
        
    def shortDescription(self):
        return self.description

    def runTest(self):
        self.failUnless(hasattr(self.hashmod, "digest_size"))
        self.assertEquals(self.hashmod.digest_size, self.expected)
        h = self.hashmod.new()
        self.failUnless(hasattr(h, "digest_size"))
        self.assertEquals(h.digest_size, self.expected)
        

# Monte Carlo Test (MCT) - see ``Description of Known Answer Test (KAT)
# and Monte Carlo Test (MCT) for SHA-3 Candidate Algorithm Submissions''
# <http://csrc.nist.gov/groups/ST/hash/documents/SHA3-KATMCT1.pdf>
class HashMonteCarloTest (unittest.TestCase):

    def __init__ (self, hashmod, description, seed, checkpoints, iterations=1000):
        unittest.TestCase.__init__(self)
        self.hashmod = hashmod
        self.description = description
        self.seed = binascii.a2b_hex(seed)
        self.checkpoints = checkpoints
        self.iterations = iterations
        self.msgcut = len(self.seed) - hashmod.digest_size

    def shortDescription(self):
        return self.description
        
    def runTest(self):
        msg = self.seed
        j = 0
        for chk in self.checkpoints:
            for i in xrange (self.iterations):
                digest = self.hashmod.new(msg).digest()
                msg = digest + msg[:self.msgcut]
            self.assertEqual (chk, binascii.b2a_hex(digest), "Failed at checkpoint n. %d" % j)
            j += 1

class HashSelfTest(unittest.TestCase):

    def __init__(self, hashmod, description, expected, input):
        unittest.TestCase.__init__(self)
        self.hashmod = hashmod
        self.expected = expected
        self.input = input
        self.description = description

    def shortDescription(self):
        return self.description

    def runTest(self):
        h = self.hashmod.new()
        h.update(self.input)

        out1 = binascii.b2a_hex(h.digest())
        out2 = h.hexdigest()

        h = self.hashmod.new(self.input)

        out3 = h.hexdigest()
        out4 = binascii.b2a_hex(h.digest())

        # PY3K: hexdigest() should return str(), and digest() bytes 
        self.assertEqual(self.expected, out1)   # h = .new(); h.update(data); h.digest()
        if sys.version_info[0] == 2:
            self.assertEqual(self.expected, out2)   # h = .new(); h.update(data); h.hexdigest()
            self.assertEqual(self.expected, out3)   # h = .new(data); h.hexdigest()
        else:
            self.assertEqual(self.expected.decode(), out2)   # h = .new(); h.update(data); h.hexdigest()
            self.assertEqual(self.expected.decode(), out3)   # h = .new(data); h.hexdigest()
        self.assertEqual(self.expected, out4)   # h = .new(data); h.digest()

        # Verify that the .new() method produces a fresh hash object, except
        # for MD5 and SHA1, which are hashlib objects.  (But test any .new()
        # method that does exist.)
        if self.hashmod.__name__ not in ('Crypto.Hash.MD5', 'Crypto.Hash.SHA1') or hasattr(h, 'new'):
            h2 = h.new()
            h2.update(self.input)
            out5 = binascii.b2a_hex(h2.digest())
            self.assertEqual(self.expected, out5)

        # Verify that Crypto.Hash.new(h) produces a fresh hash object
        h3 = Crypto.Hash.new(h)
        h3.update(self.input)
        out6 = binascii.b2a_hex(h3.digest())
        self.assertEqual(self.expected, out6)

        if hasattr(h, 'name'):
            # Verify that Crypto.Hash.new(h.name) produces a fresh hash object
            h4 = Crypto.Hash.new(h.name)
            h4.update(self.input)
            out7 = binascii.b2a_hex(h4.digest())
            self.assertEqual(self.expected, out7)

class HashTestOID(unittest.TestCase):
    def __init__(self, hashmod, oid):
        unittest.TestCase.__init__(self)
        self.hashmod = hashmod
        self.oid = oid

    def runTest(self):
        from Crypto.Signature import PKCS1_v1_5
        h = self.hashmod.new()
        self.assertEqual(PKCS1_v1_5._HASH_OIDS[h.name], self.oid)

class HashDocStringTest(unittest.TestCase):
    def __init__(self, hashmod):
        unittest.TestCase.__init__(self)
        self.hashmod = hashmod

    def runTest(self):
        docstring = self.hashmod.__doc__
        self.assert_(hasattr(self.hashmod, '__doc__'))
        self.assert_(isinstance(self.hashmod.__doc__, str))

class GenericHashConstructorTest(unittest.TestCase):
    def __init__(self, hashmod):
        unittest.TestCase.__init__(self)
        self.hashmod = hashmod

    def runTest(self):
        obj1 = self.hashmod.new("foo")
        obj2 = self.hashmod.new()
        obj3 = Crypto.Hash.new(obj1.name, "foo")
        obj4 = Crypto.Hash.new(obj1.name)
        obj5 = Crypto.Hash.new(obj1, "foo")
        obj6 = Crypto.Hash.new(obj1)
        self.assert_(isinstance(self.hashmod, obj1))
        self.assert_(isinstance(self.hashmod, obj2))
        self.assert_(isinstance(self.hashmod, obj3))
        self.assert_(isinstance(self.hashmod, obj4))
        self.assert_(isinstance(self.hashmod, obj5))
        self.assert_(isinstance(self.hashmod, obj6))

class MACSelfTest(unittest.TestCase):

    def __init__(self, hashmod, description, expected_dict, input, key, hashmods):
        unittest.TestCase.__init__(self)
        self.hashmod = hashmod
        self.expected_dict = expected_dict
        self.input = input
        self.key = key
        self.hashmods = hashmods
        self.description = description

    def shortDescription(self):
        return self.description

    def runTest(self):
        for hashname in self.expected_dict.keys():
            hashmod = self.hashmods[hashname]
            key = binascii.a2b_hex(b(self.key))
            data = binascii.a2b_hex(b(self.input))

            # Strip whitespace from the expected string (which should be in lowercase-hex)
            expected = b("".join(self.expected_dict[hashname].split()))

            h = self.hashmod.new(key, digestmod=hashmod)
            h.update(data)
            out1 = binascii.b2a_hex(h.digest())
            out2 = h.hexdigest()

            h = self.hashmod.new(key, data, hashmod)

            out3 = h.hexdigest()
            out4 = binascii.b2a_hex(h.digest())

            # Test .copy()
            h2 = h.copy()
            h.update(b("blah blah blah"))  # Corrupt the original hash object
            out5 = binascii.b2a_hex(h2.digest())    # The copied hash object should return the correct result

            # PY3K: hexdigest() should return str(), and digest() bytes 
            self.assertEqual(expected, out1)
            if sys.version_info[0] == 2:
                self.assertEqual(expected, out2)
                self.assertEqual(expected, out3)
            else:
                self.assertEqual(expected.decode(), out2)
                self.assertEqual(expected.decode(), out3)                
            self.assertEqual(expected, out4)
            self.assertEqual(expected, out5)

def make_hash_tests(module, module_name, test_data, digest_size, oid=None, mct_data=None):
    tests = []
    for i in range(len(test_data)):
        row = test_data[i]
        (expected, input) = map(b,row[0:2])
        if len(row) < 3:
            description = repr(input)
        else:
            description = row[2].encode('latin-1')
        name = "%s #%d: %s" % (module_name, i+1, description)
        tests.append(HashSelfTest(module, name, expected, input))
    name = "%s #%d: digest_size" % (module_name, i+1)
    tests.append(HashDigestSizeSelfTest(module, name, digest_size))

    if oid is not None:
        tests.append(HashTestOID(module, b(oid)))
        
    tests.append(HashDocStringTest(module))
    
    if getattr(module, 'name', None) is not None:
        tests.append(GenericHashConstructorTest(module))
        
    if mct_data is not None:
        (mct_seed, mct_checkpoints, mct_iterations) = mct_data
        tests.append (HashMonteCarloTest(module, 'Monte Carlo Test for ' + module_name,
                        mct_seed, mct_checkpoints, mct_iterations))
                        
    return tests

def make_mac_tests(module, module_name, test_data, hashmods):
    tests = []
    for i in range(len(test_data)):
        row = test_data[i]
        (key, data, results, description) = row
        name = "%s #%d: %s" % (module_name, i+1, description)
        tests.append(MACSelfTest(module, name, results, data, key, hashmods))
    return tests

# vim:set ts=4 sw=4 sts=4 expandtab:
