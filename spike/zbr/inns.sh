#!/bin/sh
# Runs inside `unshare -rn`: lo only, the whole ULA space routed locally (AnyIP), multicast on lo.
S=/tmp/claude-1000/-home-tehkode-dev/84a9af2a-090b-4f89-ad9a-91b5353e24f0/scratchpad
ip link set lo up
ip link set lo multicast on
ip -6 route add local fd00::/8 dev lo
# lo cannot loop IPv6 multicast back: the group lives on a veth pair
ip link add zbr0 type veth peer name zbr1
ip link set zbr0 up
ip link set zbr1 up
sleep 2
ZBR="--zbr-port 23106 --zbr-policy ${POLICY:-commands} --zbr-multicast-interface zbr0"
# PLACEMENT=router (spike B): the gateway runs on a second radio, a router of this network
if [ "${PLACEMENT:-coordinator}" = router ]; then COORD_ZBR=; else COORD_ZBR=$ZBR; fi
RUST_LOG=${RUST_LOG:-info,ziggurat::zbr=debug} /home/tehkode/dev/ziggurat-wt/zbr-spike/target/debug/ziggurat \
  --device /dev/serial/by-id/usb-1a86_USB_Single_Serial_5B61094735-if00 --flow-control none \
  --listen 127.0.0.1:19998 $COORD_ZBR \
  > $S/zbr/ziggurat.log 2>&1 &
sleep 2
$S/zbr-venv/bin/python -u $S/zbr/network.py ws://127.0.0.1:19998 $S/zbr/zigpy.db 15 ${PERMIT:-0} > $S/zbr/zigpy.log 2>&1 &
if [ "${PLACEMENT:-coordinator}" = router ]; then
  sleep 15
  RUST_LOG=${RUST_LOG:-info,ziggurat::zbr=debug} /home/tehkode/dev/ziggurat-wt/zbr-spike/target/debug/ziggurat \
    --device /dev/serial/by-id/usb-1a86_USB_Single_Serial_5B5E006437-if00 --flow-control none \
    --listen 127.0.0.1:19997 --zbr-router-of ws://127.0.0.1:19998 $ZBR \
    > $S/zbr/router.log 2>&1 &
fi
wait
