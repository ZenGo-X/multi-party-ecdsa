#!/usr/bin/env bash

file_as_string=`cat params.json`
n=`echo "$file_as_string" | cut -d "\"" -f 4 `
t=`echo "$file_as_string" | cut -d "\"" -f 8 `

if [[ ! -d ./bin/bs21 ]]
then
    if [[ ! -d ./bin ]]
    then
        mkdir "./bin"
    fi
    mkdir "./bin/bs21"
fi

echo -e "\n##################\n# Key generation #\n##################\n"
for i in $(seq 1 $n)
do
    echo "Key-gen for client $i out of $n"
    ./target/release/examples/bs21_keygen_client http://127.0.0.1:8001 bin/bs21/keys$i.store bin/public_key &
    sleep 1
done
