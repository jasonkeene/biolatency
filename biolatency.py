#!/usr/bin/python
#
# biolatency  Averages block device I/O latency and reports it to metron.
#
# USAGE: biolatency [-h] [-Q] [interval]
#
# Based on the biolatency tool in the BPF Compiler Collection.
# Original Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
from ctypes import c_ulong
import argparse
import sys
import grpc
import envelope_pb2
import ingress_pb2
import ingress_pb2_grpc


BPF_TEXT = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

typedef struct disk_key {
    char disk[DISK_NAME_LEN];
    u64 slot;
} disk_key_t;
BPF_HASH(start, struct request *);
BPF_ARRAY(dist, u64, 2);

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
    return 0;
}

// output
int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    u64 *tsp, delta;
    int total = 0;
    int count = 1;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&req);
    if (tsp == 0) {
        return 0;   // missed issue
    }
    delta = bpf_ktime_get_ns() - *tsp;

    // update our total and count
    u64 *totalLeaf = dist.lookup(&total);
    if (totalLeaf) {
        (*totalLeaf) += delta;
    }
    u64 *countLeaf = dist.lookup(&count);
    if (countLeaf) {
        (*countLeaf)++;
    }

    start.delete(&req);
    return 0;
}
"""


def parse_args():
    examples = """examples:
        ./biolatency 1 --cert=path/to/metron.crt --key=path/to/metron.key --ca=path/to/loggregator-ca.crt
    """
    parser = argparse.ArgumentParser(
        description="Averages block device I/O latency and reports it to metron.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples,
    )
    parser.add_argument("-Q", "--queued", action="store_true", help="include OS queued time in I/O time")
    parser.add_argument("--cert", required=True, help="path to metron cert file")
    parser.add_argument("--key", required=True, help="path to metron key file")
    parser.add_argument("--ca", required=True, help="path to ca cert file")
    parser.add_argument("interval", nargs=1, help="output interval, in seconds")
    return parser.parse_args()


def load_bpf_program(args):
    b = BPF(text=BPF_TEXT)
    if args.queued:
        b.attach_kprobe(event="blk_account_io_start", fn_name="trace_req_start")
    else:
        b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
        b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
    b.attach_kprobe(event="blk_account_io_completion",
        fn_name="trace_req_completion")
    return b


def create_envelope(average):
    return envelope_pb2.Envelope(
        source_id="biolatency",
        gauge=envelope_pb2.Gauge(
            metrics={
                "average_io_latency": envelope_pb2.GaugeValue(
                    unit="ns",
                    value=average,
                ),
            },
        ),
    )


def read_output(args, b):
    exiting = False
    dist = b.get_table("dist")
    while True:
        try:
            sleep(int(args.interval[0]))
        except KeyboardInterrupt:
            exiting = True

        total = dist[0].value
        count = dist[1].value
        dist[0] = c_ulong(0)
        dist[1] = c_ulong(0)
        average = 0
        if count != 0:
            average = float(total) / count

        print(u"{: >10.0f}ns".format(average))

        if exiting:
            sys.exit()

        yield create_envelope(average)


def start_grpc(args, b):
    with open(args.ca) as f:
        root_certificates = f.read()
    with open(args.cert) as f:
        certificate_chain = f.read()
    with open(args.key) as f:
        private_key = f.read()

    creds = grpc.ssl_channel_credentials(
        root_certificates=root_certificates,
        certificate_chain=certificate_chain,
        private_key=private_key,
    )
    channel = grpc.secure_channel("metron:3458", creds)

    stub = ingress_pb2_grpc.IngressStub(channel)
    gen = read_output(args, b)
    sender = stub.Sender(gen)


def main():
    args = parse_args()
    b = load_bpf_program(args)
    start_grpc(args, b)


if __name__ == "__main__":
    main()
