#!/usr/bin/env bash
cargo build --examples --release

n=`cat params | sed -n 1p`
t=`cat params | sed -n 2p`
params="{\"parties\":\"$n\", \"threshold\":\"$t\"}"

echo "Params: $params"
echo -n $params > params.json
echo "$0: Multi-party ECDSA parties:$n threshold:$t"
#clean
sleep 1

rm keys?.store


kill -9 $(lsof -t -i:8001)


./target/release/examples/sm_manager&

sleep 2
echo "keygen part"

for i in $(seq 1 $n)
do

echo "key gen for client $i out of $n"
./target/release/examples/gg18_keygen_client http://127.0.0.1:8001 keys$i.store &
sleep 3
done



sleep 5
echo "sign"

for i in $(seq 1 $((t+1)));
do
echo "signing for client $i out of $((t+1))"
./target/release/examples/gg18_sign_client http://127.0.0.1:8001 keys$i.store "KZen Networks" &

sleep 2
done

rm params.json
