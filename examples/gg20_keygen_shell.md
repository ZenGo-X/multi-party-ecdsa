$ docker run -d -p6831:6831/udp -p6832:6832/udp -p16686:16686 -p14268:14268 jaegertracing/all-in-one:latest
$ # browser http://localhost:16686

$ ~/hjcore/multi-party-ecdsa/target/release/examples/gg20_keygen \
    -a https://mpc.hj.io \
    -i 1 \
    -n 3 \
    -t 2 \
    -r hhge1123 \
    -o ./local-share1.json

$ ~/NO_TRACE/multi-party-ecdsa/target/release/examples/gg20_keygen \
    -a https://mpc.hj.io \
    -i 2 \
    -n 3 \
    -t 2 \
    -r hhge1123 \
    -o ./local-share2.json



$  ~/NO_TRACE/multi-party-ecdsa/target/release/examples/gg20_keygen \
    -a https://mpc.hj.io \
    -i 3 \
    -n 3 \
    -t 2 \
    -r hhge1123 \
    -o ./local-share3.json