#!/usr/bin/env python

import socket
from os import environ
from datetime import datetime
from socket import SOL_SOCKET, SO_BROADCAST, SO_REUSEADDR
from time import sleep

import click

DST_ADDR = '255.255.255.255'

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s.setblocking(True)


def run(delay, mtu, src, port, batchsize):
    s.bind((src, port))
    payload_length = mtu - 28
    payload = payload_length * b'0'
    start = datetime.now()
    for x in range(batchsize):
        sleep(delay)
        size = s.sendto(payload, (DST_ADDR, port))
        if size != payload_length:
            printf('Only {} bytes sent of packet {}'.format(size, x))
    end = datetime.now()
    return start, end, batchsize


def display_result(result):
    start, end, pkts = result
    elapsed_secs = (end-start).total_seconds()
    print('Started: ', start)
    print('Ended: ', end)
    print('Elapsed time: ', elapsed_secs)
    print('Pkts/s: ', pkts/elapsed_secs)


@click.command()
@click.option('--delay', default=0, type=float)
@click.option('--mtu', default=1500)
@click.option('--src')
@click.option('--port', default=2342)
@click.argument('batchsize', type=int)
def run_results(delay, mtu, src, port, batchsize):
    res = run(**locals())
    display_result(res)

if __name__ == '__main__':
    run_results()
