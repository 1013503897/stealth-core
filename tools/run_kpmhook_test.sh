#!/system/bin/sh
# End-to-end test of the userspace glue (lib/kpmhook) driving the KPM multi-page
# pghook table over the no-superkey syscall bridge -- the Vector/LSPlant path.
#   adb shell su -c 'sh /data/local/tmp/run_kpmhook_test.sh <APATCH_SUPERKEY>'
#
# This script only does the PRIVILEGED bootstrap (load shpte + probe + arm the
# bridge). kpmhooktool then self-hooks via the bridge with NO superkey -- exactly
# as Vector's injected native agent will. It inline-hooks vx1/vx2/vx3 (3 overrides
# on ONE page) + vy1 (another page), proves the un-hooked page-neighbors keep
# running from the clone, then partially and fully unhooks (page disarms at nov->0).
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_kpmhook_test.sh <superkey>"; exit 2; }

echo "== (re)load shpte + arm bridge =="
timeout 10 $C control shpte pgdisarm 2>/dev/null
timeout 10 $C control shpte unbridge 2>/dev/null
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm
timeout 10 $C control shpte probe
timeout 10 $C control shpte bridge   # arm the no-superkey channel for the agent

echo "== launch kpmhooktool (self-hooks via the bridge, no superkey) =="
setsid $TMP/kpmhooktool >$TMP/kh.out 2>&1 </dev/null &
TOOLPID=$!
sleep 2                              # let it init + hook + enter phase 1

echo "-- dump while phase 1 is running (expect 2 pg slots: page X nov=3, page Y nov=1) --"
timeout 10 $C control shpte dump

echo "== wait for the tool to finish all phases =="
i=0
while kill -0 "$TOOLPID" 2>/dev/null && [ $i -lt 15 ]; do sleep 1; i=$((i + 1)); done

echo "== full tool output =="
cat $TMP/kh.out

echo "-- dump after the tool exited (expect npg=0: every page disarmed) --"
timeout 10 $C control shpte dump

echo "== safety teardown =="
timeout 10 $C control shpte pgdisarm 2>/dev/null   # no-op if the tool already disarmed
timeout 10 $C control shpte unbridge
timeout 10 $C unload shpte
echo "== done =="
