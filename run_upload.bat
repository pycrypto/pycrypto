echo "--------------------------------------------------------------------------------"
echo "WINDOWS build"
echo "--------------------------------------------------------------------------------"

if "%ENABLE_UPLOAD%" == "false" (
    echo "Skipping upload"
    exit /b 0
)

@echo on

echo Creating virtual env
C:\Python27-amd64\Scripts\virtualenv -p %PYTHON_EXE% %VIRTENV_NAME_BUILD%
echo Activating
call %VIRTENV_NAME_BUILD%\Scripts\activate.bat

@echo on

echo "Python version"
python -c "import sys; print(sys.version)"

set PYTHONPATH=%WORKSPACE%

python -m pip install -U pip
python -m pip install -U setuptools
python -m pip install -U wheel
python -m pip list

rem this is a hack to force an include of stdint.h on Python 3.6
rem see http://stackoverflow.com/questions/41843266/microsoft-windows-python-3-6-pycrypto-installation-error
set CL=-FI"%VS140COMNTOOLS%..\..\VC\INCLUDE\stdint.h"

set HOME=.
rem python setup.py build_sphinx
python setup.py bdist_wheel upload -r %INDEX_SERVER% || exit /b 1

exit /b 0
