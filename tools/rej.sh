#!/bin/zsh
P=~/.foundation/sdk/foundation-sdk-1.1.0-aarch64-apple-darwin/bin/foundation-passport-drive; S=~/keyos/prime-approve/shots
pkill -f foundation-simulator; rm -f /tmp/pa.log; /tmp/runpa.sh </dev/null >/tmp/pa.out 2>&1 &
for i in {1..60}; do sleep 3; grep -aq "launch #" /tmp/pa.log 2>/dev/null && break; done; sleep 4
$P --sim tap 240 745 >/dev/null; sleep 3; $P --sim screenshot -o $S/v3-hidden.png >/dev/null
$P --sim tap 240 740 >/dev/null; sleep 3; $P --sim tap 240 594 >/dev/null; sleep 3; $P --sim screenshot -o $S/v3-tampered.png >/dev/null; sleep 3
tr -d '\r' </tmp/pa.log | grep -a "prime_approve: "
pkill -f foundation-simulator; pkill -f runpa.sh; true
