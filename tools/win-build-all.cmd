:: This is my EXPERIMENTAL script for building on Windows.
:: It only works in 32-bit Pythons for me right now.
:: It might not work for you at all.  Sorry.
:: -- dlitz
::
:: Setup instructions:
:: 1. Install the necessary Python versions via tools\win-create-pythons.sh
:: 2. Install MinGW
::    a. Go to http://www.mingw.org/
::    b. Navigate to "Downloads":
::       http://sourceforge.net/projects/mingw/files/
::    c. Install mingw-get-inst-20120426.exe and run it
::    d. Install MinGW with the "MinGW Developer Toolkit" and the "C
::       Compiler"
:: 3. Run this script with the MinGW tools in your PATH

::C:\Python21\python       setup.py -q build -c mingw32 test bdist_wininst
::C:\Python22\python       setup.py -q build -c mingw32 test bdist_wininst
::C:\Python23\python       setup.py -q build -c mingw32 test bdist_wininst
::C:\Python24\python       setup.py -q build -c mingw32 test bdist_wininst
::C:\Python25\python       setup.py -q build -c mingw32 test bdist_wininst
::C:\Python26\python       setup.py -q build -c mingw32 test bdist_wininst
C:\Python27\python       setup.py build -c mingw32 test bdist_wininst
::C:\Python30\python       setup.py -q build -c mingw32 test bdist_wininst
::C:\Python31\python       setup.py -q build -c mingw32 test bdist_wininst
::C:\Python32\python       setup.py -q build -c mingw32 test bdist_wininst
::C:\Python33\python       setup.py build -c mingw32 test bdist_wininst
:: C:\Python25-64\python setup.py -q build -c mingw32 test bdist_wininst
:: C:\Python26-64\python setup.py -q build -c mingw32 test bdist_wininst
:: C:\Python27-64\python setup.py -q build -c mingw32 test bdist_wininst
:: C:\Python30-64\python setup.py -q build -c mingw32 test bdist_wininst
:: C:\Python31-64\python setup.py -q build -c mingw32 test bdist_wininst
:: C:\Python32-64\python setup.py -q build -c mingw32 test bdist_wininst
:: C:\Python33-64\python setup.py -q build -c mingw32 test bdist_wininst
