#!/bin/sh

if [ $# -lt 3 ]
    then
        echo '<code modification log file path (could be empty string)> <pause seconds before start> <elf file>' 2>&1
        exit 1
fi

echo $1 > trace.config
echo $2 >> trace.config
shift 2
while [ $# -ne 0 ]
do
  echo "module start" >> trace.config
  echo ${1##*/}  >> trace.config
  MY_PATH=$(dirname $0)
  readelf -sW $1 | python $MY_PATH/filter_readelf.py| c++filt  | python ${MY_PATH}/post_filter.py >> trace.config
  echo "module end" >> trace.config
  shift
done
