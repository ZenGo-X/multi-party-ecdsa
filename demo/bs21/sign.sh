#!/usr/bin/env bash

file_as_string=`cat params.json`
n=`echo "$file_as_string" | cut -d "\"" -f 4 `
t=`echo "$file_as_string" | cut -d "\"" -f 8 `

if [[ ! -d ./bin/message ]]
then
    if [[ ! -d ./bin ]]
    then
        mkdir "./bin"
    fi
    echo "Testing non-interactive threshold ECDSA signing" > ./bin/message
fi

echo -e "\n###########\n# Signing #\n###########\n"
for i in $(seq 1 $((t+1)));
do
    echo "Signing locally for client $i out of $((t+1))"
    ./target/release/examples/bs21_sign_client bin/bs21/presign$i.store bin/bs21/localsig$i.store bin/message &
    sleep 1
done
