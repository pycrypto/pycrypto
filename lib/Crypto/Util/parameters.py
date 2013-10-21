# -*- coding: utf-8 -*-
#
#  Util/parameters: Utilities for processing function parameters
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

__all__ = [ 'get_parameter', 'pop_parameter' ]

import sys

def get_parameter(name, index, targs, kwargs, default=None):
    """Find a parameter in tuple and dictionary arguments
    a function receives.
    """

    param = kwargs.get(name, None)
    if len(targs) > index >= 0:
        if param:
            raise ValueError("Parameter '%s' is specified twice" % name)
        param = targs[index]
    return param or default

def pop_parameter(name, index, targs, kwargs, default=None):
    """Find a parameter in tuple and dictionary arguments
    a function receives. When found, they are removed from there.
    """

    param = None
    if kwargs.has_key(name):
        param = kwargs[name]
        del kwargs[name]
    if len(targs) > index >= 0:
        if param:
            raise ValueError("Parameter '%s' is specified twice" % name)
        param = targs[index]
        del targs[index]
    return param or default
