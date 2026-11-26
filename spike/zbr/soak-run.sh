#!/bin/sh
# SPIKE: soak through the border router. DEV (device address), INTERVAL, SOAK_TIMEOUT, NAME.
S=/tmp/claude-1000/-home-tehkode-dev/84a9af2a-090b-4f89-ad9a-91b5353e24f0/scratchpad/zbr
DEV=${DEV:-fd9e:4994:3fb:0:226e:f1ff:fe0a:e0a0}; INTERVAL=${INTERVAL:-5}; NAME=${NAME:-soak}
rm -f $S/$NAME.jsonl $S/$NAME-rss.log
( while sleep 60; do echo "$(date +%T) $(ps -eo rss,cmd | awk '/zbr-spike\/target\/debug\/ziggurat/ && !/awk/ {printf "%s ", $1}')" >> $S/$NAME-rss.log; done ) &
R=$!
cd $S && SOAK_TIMEOUT=$SOAK_TIMEOUT timeout 3700 ./ctl.sh nsenter $S/../zbr-venv/bin/python -u soak.py $DEV ff35:40:fd9e:4994:3fb::1 3600 $INTERVAL $S/$NAME.jsonl
kill $R
