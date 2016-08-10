#!/bin/bash

set -x

# show env
env

echo Purging repository
hg --config extensions.purge= clean --all --verbose

LINUX=false

if [ -e /usr/share/virtualenvwrapper/virtualenvwrapper.sh ]; then
  . /usr/share/virtualenvwrapper/virtualenvwrapper.sh
  LINUX=true
fi

# Setup virtual env
export VIRTENV_NAME_BUILD=python-upload-pycrypto-$RANDOM

INTERPRETER_ENV_NAME=${python_version}_${arch}
echo Interpreter env name: $INTERPRETER_ENV_NAME
export PYTHON_EXE=${!INTERPRETER_ENV_NAME}
echo Python interpreter: $PYTHON_EXE

if [ $LINUX == "true" ]; then
    bash run_upload.sh || exit 1
else
    cmd /c run_upload.bat || exit 1
fi

exit 0
