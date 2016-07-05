#!/bin/bash

DEVICE="$1"

rmmod ath9k
modprobe ath9k
iw "$DEVICE" set type ibss
ip l s "$DEVICE" up
