#!/bin/zsh
# usage: simshot.sh <name> [tap x y name]...
P=~/.foundation/sdk/foundation-sdk-1.1.0-aarch64-apple-darwin/bin/foundation-passport-drive
cd ~/keyos/prime-approve
pkill -f foundation-simulator; sleep 1; rm -f /tmp/pa.log
/tmp/runpa.sh </dev/null >/tmp/pa.out 2>&1 &
sleep 30
$P --sim screenshot -o shots/$1.png >/dev/null 2>&1; shift
while [ $# -ge 3 ]; do $P --sim tap $1 $2 >/dev/null 2>&1; sleep 3; $P --sim screenshot -o shots/$3.png >/dev/null 2>&1; shift 3; done
tr -d '\r' < /tmp/pa.log | grep -E "launch #|GetAppSeed|reply .* bytes|rejected|panicked at|ERR" | grep -v camera | tail -10
pkill -f foundation-simulator; pkill -f runpa.sh; true
