#!/bin/bash

set -x

echo "--------------------------------------------------------------------------------"
echo "LINUX build"
echo "--------------------------------------------------------------------------------"

if [ ${ENABLE_UPLOAD} == "false" ]
then
    echo "Skipping upload"
    exit 0
fi

virtualenv -p $PYTHON_EXE $VIRTENV_NAME_BUILD
source $VIRTENV_NAME_BUILD/bin/activate

echo "Python version"
python -c "import sys; print(sys.version)"

export PYTHONPATH=$WORKSPACE
# Build
set -e

python -m pip install -U pip
python -m pip install -U setuptools
python -m pip install -U wheel
python -m pip list

export HOME=.
#python setup.py build_sphinx
python setup.py bdist_wheel upload -r ${INDEX_SERVER}

exit 0
