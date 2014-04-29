/* -*- C -*- */
/*
 * Uses Windows CryptoAPI CryptGenRandom to get random bytes.
 * The "new" method returns an object, whose "get_bytes" method
 * can be called repeatedly to get random bytes, seeded by the
 * OS.  See the description in the comment at the end.
 * 
 * If you have the Intel Security Driver header files (icsp4ms.h)
 * for their hardware random number generator in the 810 and 820 chipsets,
 * then define HAVE_INTEL_RNG.
 *
 * =======================================================================
 * The contents of this file are dedicated to the public domain.  To the
 * extent that dedication to the public domain is not available, everyone
 * is granted a worldwide, perpetual, royalty-free, non-exclusive license
 * to exercise all rights associated with the contents of this file for
 * any purpose whatsoever.  No rights are reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * =======================================================================
 *
 */

/* Author: Mark Moraes */

#include "pycrypto_common.h"

#ifdef MS_WIN32

#define _WIN32_WINNT 0x400
#define WINSOCK

#include <windows.h>
#include <wincrypt.h>

#ifdef HAVE_INTEL_RNG
# include "icsp4ms.h"
#else
# define PROV_INTEL_SEC 22
# define INTEL_DEF_PROV "Intel Hardware Cryptographic Service Provider"
#endif

/* To-Do: store provider name and type for print/repr? */

typedef struct
{
    PyObject_HEAD
    HCRYPTPROV hcp;
} WRobject;

/* Please see PEP3123 for a discussion of PyObject_HEAD and changes made in 3.x to make it conform to Standard C.
 * These changes also dictate using Py_TYPE to check type, and PyVarObject_HEAD_INIT(NULL, 0) to initialize
 */
#define is_WRobject(v) (Py_TYPE(v) == &WRtype)
staticforward PyTypeObject WRtype;

static void
WRdealloc(PyObject *ptr)
{		
	WRobject *o = (WRobject *)ptr;

	if (! is_WRobject(ptr)) {
		PyErr_Format(PyExc_TypeError,
		    "WinRandom trying to dealloc non-WinRandom object");
		return;
	}
	if (! CryptReleaseContext(o->hcp, 0)) {
		PyErr_Format(PyExc_SystemError,
			     "CryptReleaseContext failed, error 0x%x",
			     (unsigned int) GetLastError());
		return;
	}
	/* Overwrite the contents of the object */
	o->hcp = 0;
	PyObject_Del(ptr);
}

static char winrandom__doc__[] =
"new([provider], [provtype]): Returns an object handle to Windows\n\
CryptoAPI that can be used to access a cryptographically strong\n\
pseudo-random generator that uses OS-gathered entropy.\n\
Provider is a string that specifies the Cryptographic Service Provider\n\
to use, default is the default OS CSP.\n\
provtype is an integer specifying the provider type to use, default\n\
is 1 (PROV_RSA_FULL)";

static char WR_get_bytes__doc__[] =
"get_bytes(nbytes, [userdata]]): Returns nbytes of random data\n\
from Windows CryptGenRandom.\n\
userdata is a string with any additional entropic data that the\n\
user wishes to provide.";

static WRobject *
winrandom_new(PyObject *self, PyObject *args, PyObject *kwdict)
{
	HCRYPTPROV hcp = 0;
	WRobject *res;
	char *provname = NULL;
	int provtype = PROV_RSA_FULL;
	static char *kwlist[] = { "provider", "provtype", NULL};
	
	if (!PyArg_ParseTupleAndKeywords(args, kwdict, "|si", kwlist,
					 &provname, &provtype)) {
		return NULL;
	}
	if (! CryptAcquireContext(&hcp, NULL, (LPCTSTR) provname,
				  (DWORD) provtype,
				  CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		PyErr_Format(PyExc_SystemError,
			     "CryptAcquireContext for provider \"%s\" type %i failed, error 0x%x",
			     provname? provname : "(null)", provtype,
			     (unsigned int) GetLastError());
		return NULL;
	}
	res = PyObject_New(WRobject, &WRtype);
	res->hcp = hcp;
	return res;
}

static PyObject *
WR_get_bytes(WRobject *self, PyObject *args)
{
	int n, nbytes, len = 0;
	PyObject *res;
	char *buf, *str = NULL;
	
	if (! is_WRobject(self)) {
		PyErr_Format(PyExc_TypeError,
		    "WinRandom trying to get_bytes with non-WinRandom object");
		return NULL;
	}
#ifdef HAS_NEW_BUFFER
	Py_buffer view = { 0 };
	if (!PyArg_ParseTuple(args, "i|s*", &n, &view)) {
		return NULL;
	}
	str = (char*)view.buf;
	len = view.len;
#else
	if (!PyArg_ParseTuple(args, "i|s#", &n, &str, &len)) {
		return NULL;
	}
#endif
	if (n <= 0) {
		PyErr_SetString(PyExc_ValueError, "nbytes must be positive number");
#ifdef HAS_NEW_BUFFER
		PyBuffer_Release(&view);
#endif
		return NULL;
	}
	/* Just in case char != BYTE, or userdata > desired result */
	nbytes = (((n > len) ? n : len) * sizeof(char)) / sizeof(BYTE) + 1;
	if ((buf = (char *) PyMem_Malloc(nbytes)) == NULL)
#ifdef HAS_NEW_BUFFER
		PyBuffer_Release(&view);
#endif
	    return PyErr_NoMemory();
	if (len > 0)
		memcpy(buf, str, len);
	/*
	 * if userdata > desired result, we end up getting
	 * more bytes than we really needed to return.  No
	 * easy way to avoid that: we prefer that
	 * CryptGenRandom does the distillation of userdata
	 * down to entropy, rather than trying to do it
	 * ourselves.  Since the extra bytes presumably come
	 * from an RC4 stream, they should be relatively
	 * cheap.
	 */

	if (! CryptGenRandom(self->hcp, (DWORD) nbytes, (BYTE *) buf)) {
		PyErr_Format(PyExc_SystemError,
			     "CryptGenRandom failed, error 0x%x",
			     (unsigned int) GetLastError());
		PyMem_Free(buf);
#ifdef HAS_NEW_BUFFER
		PyBuffer_Release(&view);
#endif
		return NULL;
	}

	res = PyBytes_FromStringAndSize(buf, n);
	PyMem_Free(buf);
#ifdef HAS_NEW_BUFFER
	PyBuffer_Release(&view);
#endif
	return res;
}

/* WinRandom object methods */

static PyMethodDef WRmethods[] =
{
	{"get_bytes", (PyCFunction) WR_get_bytes, METH_VARARGS,
		WR_get_bytes__doc__},
	{NULL, NULL}			/* sentinel */
};

/* winrandom module methods */

static PyMethodDef WR_mod_methods[] = {
        {"new", (PyCFunction) winrandom_new, METH_VARARGS|METH_KEYWORDS,
		winrandom__doc__},
	{NULL,      NULL}        /* Sentinel */
};

static PyObject *
WRgetattro(PyObject *s, PyObject *attr)
{
	WRobject *self = (WRobject*)s;
	if (! is_WRobject(self)) {
		PyErr_Format(PyExc_TypeError,
		    "WinRandom trying to getattr with non-WinRandom object");
		return NULL;
	}
	if (!PyString_Check(attr))
		goto generic;
	if (PyString_CompareWithASCIIString(attr, "hcp") == 0)
		return PyInt_FromLong((long) self->hcp);
  generic:
#if PYTHON_API_VERSION >= 1011          /* Python 2.2 and later */
	return PyObject_GenericGetAttr(s, attr);
#else
	if (PyString_Check(attr) < 0) {
		PyErr_SetObject(PyExc_AttributeError, attr);
		return NULL;
	}
	return Py_FindMethod(WRmethods, (PyObject *)self, PyString_AsString(attr));
#endif
}

static PyTypeObject WRtype =
 {
	PyVarObject_HEAD_INIT(NULL, 0)  /* deferred type init for compilation on Windows, type will be filled in at runtime */
 	"winrandom.WinRandom",	/*tp_name*/
 	sizeof(WRobject),	/*tp_size*/
 	0,			/*tp_itemsize*/
 	/* methods */
	(destructor) WRdealloc,		/*tp_dealloc*/
	0,				/*tp_print*/
	0,				/*tp_getattr*/
	0,				/*tp_setattr*/
	0,				/*tp_compare*/
	0,				/*tp_repr*/
	0,				/*tp_as_number */
	0,				/*tp_as_sequence */
	0,				/*tp_as_mapping */
	0,				/*tp_hash*/
	0,				/*tp_call*/
	0,				/*tp_str*/
	WRgetattro,		/*tp_getattro*/
	0,				/*tp_setattro*/
	0,				/*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT,		/*tp_flags*/
	0,				/*tp_doc*/
	0,				/*tp_traverse*/
	0,				/*tp_clear*/
	0,				/*tp_richcompare*/
	0,				/*tp_weaklistoffset*/
#if PYTHON_API_VERSION >= 1011          /* Python 2.2 and later */
	0,				/*tp_iter*/
	0,				/*tp_iternext*/
	WRmethods,		/*tp_methods*/
#endif
};

#ifdef IS_PY3K
static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	"winrandom",
	NULL,
	-1,
	WR_mod_methods,
	NULL,
	NULL,
	NULL,
	NULL
 };
#endif

PyMODINIT_FUNC
#ifdef IS_PY3K
PyInit_winrandom()
#else
initwinrandom()
#endif
{
	PyObject *m = NULL;

	if (PyType_Ready(&WRtype) < 0)
		goto errout;

	/* Initialize the module */
#ifdef IS_PY3K
	m = PyModule_Create(&moduledef);
#else
	m = Py_InitModule("winrandom", WR_mod_methods);
#endif
	if (m == NULL)
		goto errout;

	/* define Windows CSP Provider Types */
#ifdef PROV_RSA_FULL
	PyModule_AddIntConstant(m, "PROV_RSA_FULL", PROV_RSA_FULL);
#endif
#ifdef PROV_RSA_SIG
	PyModule_AddIntConstant(m, "PROV_RSA_SIG", PROV_RSA_SIG);
#endif
#ifdef PROV_DSS
	PyModule_AddIntConstant(m, "PROV_DSS", PROV_DSS);
#endif
#ifdef PROV_FORTEZZA
	PyModule_AddIntConstant(m, "PROV_FORTEZZA", PROV_FORTEZZA);
#endif
#ifdef PROV_MS_EXCHANGE
	PyModule_AddIntConstant(m, "PROV_MS_EXCHANGE", PROV_MS_EXCHANGE);
#endif
#ifdef PROV_SSL
	PyModule_AddIntConstant(m, "PROV_SSL", PROV_SSL);
#endif
#ifdef PROV_RSA_SCHANNEL
	PyModule_AddIntConstant(m, "PROV_RSA_SCHANNEL", PROV_RSA_SCHANNEL);
#endif
#ifdef PROV_DSS_DH
	PyModule_AddIntConstant(m, "PROV_DSS_DH", PROV_DSS_DH);
#endif
#ifdef PROV_EC_ECDSA_SIG
	PyModule_AddIntConstant(m, "PROV_EC_ECDSA_SIG", PROV_EC_ECDSA_SIG);
#endif
#ifdef PROV_EC_ECNRA_SIG
	PyModule_AddIntConstant(m, "PROV_EC_ECNRA_SIG", PROV_EC_ECNRA_SIG);
#endif
#ifdef PROV_EC_ECDSA_FULL
	PyModule_AddIntConstant(m, "PROV_EC_ECDSA_FULL", PROV_EC_ECDSA_FULL);
#endif
#ifdef PROV_EC_ECNRA_FULL
	PyModule_AddIntConstant(m, "PROV_EC_ECNRA_FULL", PROV_EC_ECNRA_FULL);
#endif
#ifdef PROV_SPYRUS_LYNKS
	PyModule_AddIntConstant(m, "PROV_SPYRUS_LYNKS", PROV_SPYRUS_LYNKS);
#endif
#ifdef PROV_INTEL_SEC
	PyModule_AddIntConstant(m, "PROV_INTEL_SEC", PROV_INTEL_SEC);
#endif

	/* Define Windows CSP Provider Names */
#ifdef MS_DEF_PROV
	PyModule_AddStringConstant(m, "MS_DEF_PROV", MS_DEF_PROV);
#endif
#ifdef MS_ENHANCED_PROV
	PyModule_AddStringConstant(m, "MS_ENHANCED_PROV", MS_ENHANCED_PROV);
#endif
#ifdef MS_DEF_RSA_SIG_PROV
	PyModule_AddStringConstant(m, "MS_DEF_RSA_SIG_PROV",
				   MS_DEF_RSA_SIG_PROV);
#endif
#ifdef MS_DEF_RSA_SCHANNEL_PROV
	PyModule_AddStringConstant(m, "MS_DEF_RSA_SCHANNEL_PROV",
				   MS_DEF_RSA_SCHANNEL_PROV);
#endif
#ifdef MS_ENHANCED_RSA_SCHANNEL_PROV
	PyModule_AddStringConstant(m, "MS_ENHANCED_RSA_SCHANNEL_PROV",
				   MS_ENHANCED_RSA_SCHANNEL_PROV);
#endif
#ifdef MS_DEF_DSS_PROV
	PyModule_AddStringConstant(m, "MS_DEF_DSS_PROV", MS_DEF_DSS_PROV);
#endif
#ifdef MS_DEF_DSS_DH_PROV
	PyModule_AddStringConstant(m, "MS_DEF_DSS_DH_PROV",
				   MS_DEF_DSS_DH_PROV);
#endif
#ifdef INTEL_DEF_PROV
	PyModule_AddStringConstant(m, "INTEL_DEF_PROV", INTEL_DEF_PROV);
#endif

out:
	/* Final error check */
	if (m == NULL && !PyErr_Occurred()) {
		PyErr_SetString(PyExc_ImportError, "can't initialize module");
		goto errout;
	}

	/* Free local objects here */

	/* Return */
#ifdef IS_PY3K
	return m;
#else
	return;
#endif

errout:
	/* Free the module and other global objects here */
	Py_CLEAR(m);
	goto out;
}
/*

CryptGenRandom usage is described in
http://msdn.microsoft.com/library/en-us/security/security/cryptgenrandom.asp
and many associated pages on Windows Cryptographic Service
Providers, which say:

	With Microsoft CSPs, CryptGenRandom uses the same
	random number generator used by other security
	components. This allows numerous processes to
	contribute to a system-wide seed. CryptoAPI stores
	an intermediate random seed with every user. To form
	the seed for the random number generator, a calling
	application supplies bits it might havefor instance,
	mouse or keyboard timing inputthat are then added to
	both the stored seed and various system data and
	user data such as the process ID and thread ID, the
	system clock, the system time, the system counter,
	memory status, free disk clusters, the hashed user
	environment block. This result is SHA-1 hashed, and
	the output is used to seed an RC4 stream, which is
	then used as the random stream and used to update
	the stored seed.

The only other detailed description I've found of the
sources of randomness for CryptGenRandom is this excerpt
from a posting
http://www.der-keiler.de/Newsgroups/comp.security.ssh/2002-06/0169.html

From: Jon McClelland (dowot69@hotmail.com) 
Date: 06/12/02 
... 
 
Windows, call a function such as CryptGenRandom, which has two of 
the properties of a good random number generator, unpredictability and 
even value distribution. This function, declared in Wincrypt.h, is 
available on just about every Windows platform, including Windows 95 
with Internet Explorer 3.02 or later, Windows 98, Windows Me, Windows 
CE v3, Windows NT 4, Windows 2000, and Windows XP. 
 
CryptGenRandom gets its randomness, also known as entropy, from many 
sources in Windows 2000, including the following: 
The current process ID (GetCurrentProcessID). 
The current thread ID (GetCurrentThreadID). 
The ticks since boot (GetTickCount). 
The current time (GetLocalTime). 
Various high-precision performance counters (QueryPerformanceCounter). 
A Message Digest 4 (MD4) hash of the user's environment block, which 
includes username, computer name, and search path. 
 
High-precision internal CPU counters, such as RDTSC, RDMSR, RDPMC (x86 
only-more information about these counters is at 
developer.intel.com/software/idap/resources/technical_collateral/pentiumii/RDTSCPM1.HTM 
<http://developer.intel.com>). 
 
Low-level system information, such as idle time, kernel time, 
interrupt times, commit limit, page read count, cache read count, 
nonpaged pool allocations, alignment fixup count, operating system 
lookaside information. 
 
Such information is added to a buffer, which is hashed using MD4 and 
used as the key to modify a buffer, using RC4, provided by the user. 
(Refer to the CryptGenRandom documentation in the Platform SDK for 
more information about the user-provided buffer.) Hence, if the user 
provides additional data in the buffer, this is used as an element in 
the witches brew to generate the random data. The result is a 
cryptographically random number generator. 
Also, note that if you plan to sell your software to the United States 
federal government, you'll need to use FIPS 140-1-approved algorithms. 
The default versions of CryptGenRandom in Microsoft Windows CE v3, 
Windows 95, Windows 98, Windows Me, Windows 2000, and Windows XP are 
FIPS-approved. Obviously FIPS-140 compliance is necessary but not 
sufficient to provide a properly secure source of random data. 
 
*/
/*
[Update: 2007-11-13]
CryptGenRandom does not necessarily provide forward secrecy or reverse
secrecy.  See the paper by Leo Dorrendorf and Zvi Gutterman and Benny
Pinkas, _Cryptanalysis of the Random Number Generator of the Windows
Operating System_, Cryptology ePrint Archive, Report 2007/419,
http://eprint.iacr.org/2007/419
*/

#endif /* MS_WIN32 */
