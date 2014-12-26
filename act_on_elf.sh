#!/bin/sh

if [ $# -ne 3 ]
    then
        echo '<elf file> <code modification log file path (could be empty string)> <pause seconds before start>' 2>&1
        exit 1
fi

echo $2 > trace.config
echo $3 >> trace.config
echo ${1##*/}  >> trace.config

readelf -sW $1 | python $(dirname $0)/filter_readelf.py| c++filt  >> trace.config
