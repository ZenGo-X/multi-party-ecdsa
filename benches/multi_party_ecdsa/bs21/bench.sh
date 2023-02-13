#!/usr/bin/env bash 

# To do: Give full reference for [BS21]. 

SCRIPT="./demo/run21.sh"
PROTOCOL="BS21"
DIR="./benches/multi_party_ecdsa"
BENCH_DIR="./benches/multi_party_ecdsa/bs21/hyperfine"

MAIL="monjipour@gmail.com"
EXT="csv"

# After warmup, to avoid outliers, this program benchmarks one by one shell scripts in SCRIPT_DIR.
# Each of them corresponds to one of the steps in the protocol, without rool-call, of threshold signature algorithm in [BS21].
# Benchmark results are stored in markdown files in BENCH_DIR.

# The script employs the following dependencies:
# hyperfine - command-line benchmarking tool

# Define basic parameters: thresold t and number of parties n.
# Any group of t+1 out of n parties is required to sign transations

if [ -z "$1" ]
then
    set "10"
else 
	if (($1 < 3)); then set "2"; fi
fi

ssmtp ${MAIL} < ${DIR}/mail.txt

echo -e "command,mean,stddev,median,user,system,min,max,n,t" > ${BENCH_DIR}/${PROTOCOL}.${EXT}

for ((n=10;n<=$1;n++))
do
	for ((t=1;t<$n;t++))
	do
		echo -e "{\"parties\":\"$n\", \"threshold\":\"$t\"}\n" > params.json
		cat params.json
		hyperfine --warmup 3 --export-${EXT} ${BENCH_DIR}/temp.${EXT}  ${SCRIPT}
		
		echo -e $(tail -n 1 ${BENCH_DIR}/temp.${EXT} | sed 's/["\n\r]//g')",$n,$t" >> ${BENCH_DIR}/${PROTOCOL}.${EXT}
	done
done

ssmtp ${MAIL} < ${DIR}/mail.txt
rm ${BENCH_DIR}/temp.${EXT}
