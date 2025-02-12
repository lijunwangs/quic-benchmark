# quic-benchmark
Tool to bench mark QUINN quic performance

quic_benchmark 1.0.0

USAGE:
    quic-benchmark [FLAGS] [OPTIONS]

FLAGS:
        --client-only    Run only the client
    -h, --help           Prints help information
        --server-only    Run only the server
    -V, --version        Prints version information

OPTIONS:
        --cert <cert>                        Server certificate
        --key <key>                          Server key
        --num-endpoints <num-endpoints>      Number of endpoints on server side [default: 8]
        --num-packets <num-packets>          Number of packets per sender thread [default: 10000]
        --num-threads <num-threads>          Number of sender threads [default: 4]
        --server-address <server-address>    Server address (IP:port) for client mode [default: 0.0.0.0:11228]