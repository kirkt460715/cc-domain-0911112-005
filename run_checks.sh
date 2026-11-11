#!/bin/sh
set -eu
python3 -m compileall -q trialvault
python3 -m unittest discover -s tests -v
python3 -m trialvault demo
