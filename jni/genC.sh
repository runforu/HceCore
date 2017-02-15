#!/bin/bash

old_dir=$PWD
cd "$(dirname "$0")"
./gen_c.exe
cd ${old_dir}

