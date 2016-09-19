#!/usr/bin/env python

import socket
from os import environ
from datetime import datetime
from socket import SOL_SOCKET, SO_BROADCAST
from time import sleep

import click

DST_ADDR = '255.255.255.255'

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setblocking(True)


def run(delay, payload_length, src, port, batchsize):
    s.bind((src, port))
    payload = payload_length * b'0'
    start = datetime.now()
    for x in range(batchsize):
        sleep(delay)
        size = s.sendto(payload, (DST_ADDR, port))
        if size < payload_length:
            printf('Only {} bytes sent of packet {}'.format(size, x))
    end = datetime.now()
    return start, end, batchsize


def display_result(result):
    start = result[0]
    end = result[1]
    pkts = result[2]
    elapsed_secs = (end-start).total_seconds()
    print('Started: ', start)
    print('Ended: ', end)
    print('Elapsed time: ', elapsed_secs)
    print('Pkts/s: ', pkts/elapsed_secs)


@click.command()
@click.option('--delay', default=0, type=int)
@click.option('--payload_length', default=1472)
@click.option('--src')
@click.option('--port', default=2342)
@click.argument('batchsize', type=int)
def run_results(delay, payload_length, src, port, batchsize):
    res = run(**locals())
    display_result(res)

if __name__ == '__main__':
    run_results()
