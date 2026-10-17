#!/bin/zsh
# usage: step.sh <outname> <cmd...>  (cmds: "tap x y" or "swipe sx sy ex ey")
P=~/.foundation/sdk/foundation-sdk-1.1.0-aarch64-apple-darwin/bin/foundation-passport-drive
cd ~/keyos/prime-approve
pkill -f foundation-simulator; sleep 1; rm -f /tmp/pa.log
/tmp/runpa.sh </dev/null >/tmp/pa.out 2>&1 &
sleep 30
out=$1; shift
for c in "$@"; do eval "$P --sim $c" >/dev/null 2>&1; sleep 4; done
$P --sim screenshot -o shots/$out.png >/dev/null 2>&1
tr -d '\r' < /tmp/pa.log | grep -E "prime_approve|panicked at" | grep -v camera | tail -8
pkill -f foundation-simulator; pkill -f runpa.sh; true
