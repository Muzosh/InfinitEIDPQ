#!/bin/bash

set -e
set -u

/usr/bin/find src/ lib/ -iname '*.hpp' -o -iname '*.h' -o -iname '*.cpp' | xargs clang-format -i