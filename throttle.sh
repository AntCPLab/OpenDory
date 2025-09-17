#!/bin/bash
DEV=lo
if [ "$1" == "del" ]
then
	sudo tc qdisc del dev $DEV root
fi

if [ "$1" == "lan" ]
then
sudo tc qdisc del dev $DEV root
sudo tc qdisc add dev $DEV root handle 1: tbf rate 10000mbit burst 100000 limit 10000
sudo tc qdisc add dev $DEV parent 1:1 handle 10: netem delay 0.1msec
fi
if [ "$1" == "wan" ]
then
sudo tc qdisc del dev $DEV root
sudo tc qdisc add dev $DEV root handle 1: tbf rate 5mbit burst 100000 limit 10000
sudo tc qdisc add dev $DEV parent 1:1 handle 10: netem delay 0.1msec
fi
if [ "$1" == "wan1" ]
then
sudo tc qdisc del dev $DEV root
sudo tc qdisc add dev $DEV root handle 1: tbf rate 1024mbit burst 100000 limit 10000
sudo tc qdisc add dev $DEV parent 1:1 handle 10: netem delay 0.1msec
fi
if [ "$1" == "wan2" ]
then
sudo tc qdisc del dev $DEV root
sudo tc qdisc add dev $DEV root handle 1: tbf rate 500mbit burst 100000 limit 10000
sudo tc qdisc add dev $DEV parent 1:1 handle 10: netem delay 0.1msec
fi
if [ "$1" == "wan3" ]
then
sudo tc qdisc del dev $DEV root
sudo tc qdisc add dev $DEV root handle 1: tbf rate 100mbit burst 100000 limit 10000
sudo tc qdisc add dev $DEV parent 1:1 handle 10: netem delay 0.1msec
fi
if [ "$1" == "wan4" ]
then
sudo tc qdisc del dev $DEV root
sudo tc qdisc add dev $DEV root handle 1: tbf rate 50mbit burst 100000 limit 10000
sudo tc qdisc add dev $DEV parent 1:1 handle 10: netem delay 0.1msec
fi
if [ "$1" == "wan5" ]
then
sudo tc qdisc del dev $DEV root
sudo tc qdisc add dev $DEV root handle 1: tbf rate 10mbit burst 100000 limit 10000
sudo tc qdisc add dev $DEV parent 1:1 handle 10: netem delay 0.1msec
fi
if [ "$1" == "wan6" ]
then
sudo tc qdisc del dev $DEV root
sudo tc qdisc add dev $DEV root handle 1: tbf rate 5mbit burst 100000 limit 10000
sudo tc qdisc add dev $DEV parent 1:1 handle 10: netem delay 0.1msec
fi