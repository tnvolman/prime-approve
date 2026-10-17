#!/bin/zsh
# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
P=~/.foundation/sdk/foundation-sdk-1.1.0-aarch64-apple-darwin/bin/foundation-passport-drive
cd ~/keyos/prime-approve
pkill -f foundation-simulator; sleep 1; rm -f /tmp/pa.log
/tmp/runpa.sh </dev/null >/tmp/pa.out 2>&1 &
sleep 30
# approve path
$P --sim tap 240 590 >/dev/null 2>&1; sleep 3
$P --sim swipe 90 655 445 655 --duration-ms 900 --steps 30 >/dev/null 2>&1; sleep 4
$P --sim screenshot -o shots/result.png >/dev/null 2>&1
tr -d '\r' < /tmp/pa.log | grep -E "launch #|reply|rejected|panicked at|ERR" | grep -v camera | tail -10
pkill -f foundation-simulator; pkill -f runpa.sh; sleep 2
# relaunch: tampered then (after relaunch) replayed
rm -f /tmp/pa.log; /tmp/runpa.sh </dev/null >/tmp/pa.out 2>&1 &
sleep 30
$P --sim tap 240 670 >/dev/null 2>&1; sleep 3
$P --sim screenshot -o shots/tampered.png >/dev/null 2>&1
pkill -f foundation-simulator; pkill -f runpa.sh; sleep 2
rm -f /tmp/pa.log; /tmp/runpa.sh </dev/null >/tmp/pa.out 2>&1 &
sleep 30
$P --sim screenshot -o shots/home-after.png >/dev/null 2>&1
$P --sim tap 240 745 >/dev/null 2>&1; sleep 3
$P --sim screenshot -o shots/replayed.png >/dev/null 2>&1
tr -d '\r' < /tmp/pa.log | grep -E "launch #|reply|rejected|panicked at|ERR" | grep -v camera | tail -10
pkill -f foundation-simulator; pkill -f runpa.sh; true
