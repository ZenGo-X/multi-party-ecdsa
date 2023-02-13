#!/usr/bin/env bash 

SCRIPT_DIR="./demo/bs23"
PROTOCOL="BS23"
DIR="./benches/multi_party_ecdsa"
BENCH_DIR="./benches/multi_party_ecdsa/bs23/hyperfine"

MAIL="monjipour@gmail.com"
EXT="csv"
REPS="50"

# After warmup, to avoid outliers, this program benchmarks one by one shell scripts in SCRIPT_DIR.
# Each of them corresponds to one of the steps in the protocol, without rool-call, of threshold signature algorithm in [BS23].
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

if [[ ! -d ${BENCH_DIR}/${PROTOCOL}_presign.${EXT} ]]
then
    if [[ ! -d ${BENCH_DIR} ]]
    then
        mkdir ${BENCH_DIR}
    fi
    touch ${BENCH_DIR}/${PROTOCOL}_presign.${EXT}
fi
if [[ ! -d ${BENCH_DIR}/${PROTOCOL}_keygen.${EXT} ]]
then
    touch ${BENCH_DIR}/${PROTOCOL}_keygen.${EXT}
fi
if [[ ! -d ${BENCH_DIR}/${PROTOCOL}_sign.${EXT} ]]
then
    touch ${BENCH_DIR}/${PROTOCOL}_sign.${EXT}
fi
if [[ ! -d ${BENCH_DIR}/${PROTOCOL}_compile.${EXT} ]]
then
    touch ${BENCH_DIR}/${PROTOCOL}_compile.${EXT}
fi
echo -e "command,mean,stddev,median,user,system,min,max,n,t,r" > ${BENCH_DIR}/${PROTOCOL}_keygen.${EXT}
echo -e "command,mean,stddev,median,user,system,min,max,n,t,r" > ${BENCH_DIR}/${PROTOCOL}_presign.${EXT}
echo -e "command,mean,stddev,median,user,system,min,max,n,t,r" > ${BENCH_DIR}/${PROTOCOL}_sign.${EXT}
echo -e "command,mean,stddev,median,user,system,min,max,n,t,r" > ${BENCH_DIR}/${PROTOCOL}_compile.${EXT}

killall sm_manager bs23_keygen_client bs23_presign_client bs23_sign_client bs23_compile_sig 2> /dev/null
# Start sm_manager
./target/release/examples/sm_manager &
sleep 2
for ((n=10;n<=$1;n++))
do
	for ((t=1;t<$n;t++))
	do
		echo -e "\nBenchmark of ($n, $t)"
		echo -e "{\"parties\":\"$n\", \"threshold\":\"$t\"}\n" > params.json

		# Keygen
		hyperfine --warmup 3 -m 5 --export-${EXT} ${BENCH_DIR}/temp.${EXT}  ${SCRIPT_DIR}/keygen.sh
		echo -e $(tail -n 1 ${BENCH_DIR}/temp.${EXT} | sed 's/["\n\r]//g')",$n,$t,5" >> ${BENCH_DIR}/${PROTOCOL}_keygen.${EXT}
		sleep 10

		# Presign
		hyperfine --warmup 5 -m ${REPS} --export-${EXT} ${BENCH_DIR}/temp.${EXT}  ${SCRIPT_DIR}/presign.sh
		echo -e $(tail -n 1 ${BENCH_DIR}/temp.${EXT} | sed 's/["\n\r]//g')",$n,$t,${REPS}" >> ${BENCH_DIR}/${PROTOCOL}_presign.${EXT}
		sleep 10

		# Sign
		hyperfine --warmup 5 -m ${REPS} --export-${EXT} ${BENCH_DIR}/temp.${EXT}  ${SCRIPT_DIR}/sign.sh
		echo -e $(tail -n 1 ${BENCH_DIR}/temp.${EXT} | sed 's/["\n\r]//g')",$n,$t,${REPS}" >> ${BENCH_DIR}/${PROTOCOL}_sign.${EXT}
		sleep 10

		# Compile Sig
		hyperfine --warmup 5 -m ${REPS} --export-${EXT} ${BENCH_DIR}/temp.${EXT}  ${SCRIPT_DIR}/compile_sig.sh
		echo -e $(tail -n 1 ${BENCH_DIR}/temp.${EXT} | sed 's/["\n\r]//g')",$n,$t,${REPS}" >> ${BENCH_DIR}/${PROTOCOL}_compile.${EXT}
		sleep 10
	done
done
# Kill sm_manager
killall sm_manager 2> /dev/null

ssmtp ${MAIL} < ${DIR}/mail.txt
rm ${BENCH_DIR}/temp.${EXT}
