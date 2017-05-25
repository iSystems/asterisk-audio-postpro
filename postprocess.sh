#!/bin/bash
set -e

cd "$(dirname "$(readlink -f "$0")")"
source env/bin/activate

python postprocess.py $@
