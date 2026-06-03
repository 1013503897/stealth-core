#!/system/bin/sh
# RV-2 multi-page (clean-bounded region) clone test (device-side, root).
#   adb shell su -c 'sh /data/local/tmp/run_rgn_test.sh <APATCH_SUPERKEY>'
# Privileged setup arms the bridge; rgntool then self-hooks a PAGE-SPANNING function
# (spanfn, ~1100 insns) over the bridge with no superkey. Proof the multi-page region
# clone works: the hooked spanfn's backup returns n+1100 (its FULL body ran via the
# clone -- a single-page clone would crash/return wrong), its page-neighbor nbfn (on
# the region's 2nd page) returns n*2 normally, and `dump` shows a slot with npages>1.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_rgn_test.sh <superkey>"; exit 2; }

echo "== (re)load shpte + arm bridge =="
timeout 10 $C control shpte pgdisarm 2>/dev/null
timeout 10 $C control shpte unbridge 2>/dev/null
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm
timeout 10 $C control shpte probe
timeout 10 $C control shpte bridge

echo "== launch rgntool (self-hooks a page-spanning fn via the bridge) =="
setsid $TMP/rgntool >$TMP/rgn.out 2>&1 </dev/null &
TOOLPID=$!
sleep 2

echo "-- dump while hooked (expect a slot with npages>1) --"
timeout 10 $C control shpte dump

echo "== wait for the tool to finish =="
i=0
while kill -0 "$TOOLPID" 2>/dev/null && [ $i -lt 12 ]; do sleep 1; i=$((i + 1)); done

echo "== full tool output =="
cat $TMP/rgn.out

echo "-- dump after exit (expect npg=0) --"
timeout 10 $C control shpte dump

echo "== safety teardown =="
timeout 10 $C control shpte pgdisarm 2>/dev/null
timeout 10 $C control shpte unbridge
timeout 10 $C unload shpte
echo "== done =="
