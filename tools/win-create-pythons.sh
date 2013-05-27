#!/bin/bash
# Experimental script used to install multiple versions of Python on
# Windows for testing PyCrypto.
# Edit it to suit your needs.
# by Dwayne Litzenberger
#
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

# Designed to run under "Git Bash" (mingw bash) on Windows
set -e

PREFIX=${PREFIX:-$(perl -e 'use Cwd; use File::Basename; print dirname(Cwd::abs_path($ARGV[0]));' "$0")/py}

# Unexport vars
export -n PREFIX

#
# Download
#
mkdir -p "$PREFIX/archives"
cd "$PREFIX/archives"

for url in \
    http://www.python.org/ftp/python/2.1.2/Python-2.1.2.exe \
    http://www.python.org/ftp/python/2.2.3/Python-2.2.3.exe \
    http://www.python.org/ftp/python/2.3.5/Python-2.3.5.exe \
    http://www.python.org/ftp/python/2.4.4/python-2.4.4.msi \
    http://www.python.org/ftp/python/2.5.4/python-2.5.4.msi \
    http://www.python.org/ftp/python/2.5.4/python-2.5.4.amd64.msi \
    http://www.python.org/ftp/python/2.6.6/python-2.6.6.msi \
    http://www.python.org/ftp/python/2.6.6/python-2.6.6.amd64.msi \
    http://www.python.org/ftp/python/2.7.3/python-2.7.3.msi \
    http://www.python.org/ftp/python/2.7.3/python-2.7.3.amd64.msi \
    http://www.python.org/ftp/python/3.0.1/python-3.0.1.msi \
    http://www.python.org/ftp/python/3.0.1/python-3.0.1.amd64.msi \
    http://www.python.org/ftp/python/3.1.4/python-3.1.4.msi \
    http://www.python.org/ftp/python/3.1.4/python-3.1.4.amd64.msi \
    http://www.python.org/ftp/python/3.2.3/python-3.2.3.msi \
    http://www.python.org/ftp/python/3.2.3/python-3.2.3.amd64.msi \
    http://www.python.org/ftp/python/3.3.0/python-3.3.0.msi \
    http://www.python.org/ftp/python/3.3.0/python-3.3.0.amd64.msi
do
    bn=`basename "$url"`
    if [ -e "$PREFIX/archives/$bn" ] ; then
        echo "Already downloaded $url ."
    else
        echo "Downloading $url ..."
        curl --fail --continue-at - --output "$PREFIX/archives/$bn.tmp" "$url"
        mv -f "$PREFIX/archives/$bn.tmp" "$PREFIX/archives/$bn"
    fi
done

# Check MD5 checksums (transcribed from www.python.org)
md5sum -c <<'EOF'
cd03fd7506bc604c441f4552b3f4f5d4 *Python-2.1.2.exe
d76e774a4169794ae0d7a8598478e69e *Python-2.2.3.exe
ba6f9eb9da40ad23bc631a1f31149a01 *Python-2.3.5.exe
8b1517fdbf287d402ac06cc809abfad6 *python-2.4.4.msi
b4bbaf5a24f7f0f5389706d768b4d210 *python-2.5.4.msi
b1e1e2a43324b0b6ddaff101ecbd8913 *python-2.5.4.amd64.msi
80b1ef074a3b86f34a2e6b454a05c8eb *python-2.6.6.msi
6f91625fe7744771da04dd1cabef0adc *python-2.6.6.amd64.msi
c846d7a5ed186707d3675564a9838cc2 *python-2.7.3.msi
d11d4aeb7e5425bf28f28ab1c7452886 *python-2.7.3.amd64.msi
ffce874eb1a832927fb705b84720bfc6 *python-3.0.1.msi
be8f57265e1419330965692a4fa15d9a *python-3.0.1.amd64.msi
142acb595152b322f5341045327a42b8 *python-3.1.4.msi
829794fc7902880e4d55c7937c364541 *python-3.1.4.amd64.msi
c176c60e6d780773e3085ee824b3078b *python-3.2.3.msi
01aae7d96fa1c5a585f596b20233c6eb *python-3.2.3.amd64.msi
70062e4b9a1f959f5e07555e471c5657 *python-3.3.0.msi
5129376df1c56297a80e69a1a6144b4e *python-3.3.0.amd64.msi
EOF

#
# Install
#
set -x
cmd //c Python-2.1.2.exe
cmd //c Python-2.2.3.exe
cmd //c Python-2.3.5.exe
msiexec //passive //i python-2.4.4.msi       ALLUSERS=1
msiexec //passive //i python-2.5.4.msi       ALLUSERS=1
msiexec //passive //i python-2.5.4.amd64.msi ALLUSERS=1 TARGETDIR=C:\\Python25-64\\
msiexec //passive //i python-2.6.6.msi       ALLUSERS=1
msiexec //passive //i python-2.6.6.amd64.msi ALLUSERS=1 TARGETDIR=C:\\Python26-64\\
msiexec //passive //i python-2.7.3.msi       ALLUSERS=1
msiexec //passive //i python-2.7.3.amd64.msi ALLUSERS=1 TARGETDIR=C:\\Python27-64\\
msiexec //passive //i python-3.0.1.msi       ALLUSERS=1
msiexec //passive //i python-3.0.1.amd64.msi ALLUSERS=1 TARGETDIR=C:\\Python30-64\\
msiexec //passive //i python-3.1.4.msi       ALLUSERS=1
msiexec //passive //i python-3.1.4.amd64.msi ALLUSERS=1 TARGETDIR=C:\\Python31-64\\
msiexec //passive //i python-3.2.3.msi       ALLUSERS=1
msiexec //passive //i python-3.2.3.amd64.msi ALLUSERS=1 TARGETDIR=C:\\Python32-64\\
msiexec //passive //i python-3.3.0.msi       ALLUSERS=1
msiexec //passive //i python-3.3.0.amd64.msi ALLUSERS=1 TARGETDIR=C:\\Python33-64\\
set +x
