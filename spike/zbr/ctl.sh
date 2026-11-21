#!/bin/sh
# SPIKE: start/stop the border-router stack in its own rootless network namespace.
S=/tmp/claude-1000/-home-tehkode-dev/84a9af2a-090b-4f89-ad9a-91b5353e24f0/scratchpad/zbr
case "$1" in
stop)
  G=$(ps -eo pgid,cmd | awk '$2=="/bin/sh" && $3=="./inns.sh" {print $1; exit}'); [ -n "$G" ] && kill -- -$G; sleep 2 ;;
start)
  stty -F /dev/serial/by-id/usb-1a86_USB_Single_Serial_5B61094735-if00 -hupcl
  rm -f $S/zigpy.log
  cd $S && POLICY=${POLICY:-commands} PERMIT=${PERMIT:-0} setsid unshare -rn ./inns.sh > $S/inns.out 2>&1 &
  timeout 60 sh -c "until grep -qE 'KNOWN 20|PERMIT|Traceback' $S/zigpy.log 2>/dev/null; do sleep 2; done"
  sleep 2; grep -E "NETWORK|KNOWN|PERMIT|Error" $S/zigpy.log
  sed 's/\x1b\[[0-9;]*m//g' $S/ziggurat.log | grep -E "ZBR: EPID" | tail -1 ;;
nsenter)
  shift; exec nsenter -t $(ps -eo pid,cmd | awk '$2 ~ /zbr-spike\/target\/debug\/ziggurat$/ {print $1; exit}') -U -n --preserve-credentials "$@" ;;
esac
