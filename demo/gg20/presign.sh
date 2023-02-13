#!/usr/bin/env bash

file_as_string=`cat params.json`
n=`echo "$file_as_string" | cut -d "\"" -f 4 `
t=`echo "$file_as_string" | cut -d "\"" -f 8 `

echo -e "\n###############\n# Pre-signing #\n###############\n"
for i in $(seq 1 $((t+1)));
do
    echo "Pre-signing for client $i out of $(($t+1))"
    ./target/release/examples/gg20_presign_client http://127.0.0.1:8001 bin/gg20/keys$i.store bin/gg20/presign$i.store &
    sleep 1
done
