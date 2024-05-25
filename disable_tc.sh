#!/bin/bash
sudo -E tc qdisc del dev $INTERFACE handle ffff: parent ffff:fff1
