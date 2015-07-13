#!/bin/bash

set -e
set -x

source ~/.venv/bin/activate
tox -e $TOX_ENV -- $TOX_FLAGS
