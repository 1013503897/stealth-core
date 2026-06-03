#!/system/bin/sh
# Shared-page inline hook test (device-side, root).
#   adb shell su -c 'sh /data/local/tmp/run_pagehook_test.sh <APATCH_SUPERKEY>'
# funcA/funcB/funcC share a page. We recompile the whole page, UXN-trap it, and
# `pagehook` routes ONLY funcA's entry to replaceA (which calls backup = clone's
# funcA). Proof: funcA -> [HOOK A] + [A] (via backup) + [HOOK A done], while
# funcB/funcC keep printing normally (from the clone) -- a process-wide inline
# hook of one function that shares its page with others, .text untouched.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_pagehook_test.sh <superkey>"; exit 2; }

echo "== load shpte =="
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm

echo "== launch pagetool =="
setsid $TMP/pagetool >$TMP/ph.out 2>&1 </dev/null &
sleep 1
head -1 $TMP/ph.out
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/ph.out | head -1)
PAGE=$(sed -n 's/.*page=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/ph.out | head -1)
RA=$(sed -n 's/.*replaceA=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/ph.out | head -1)
CLONE=$(sed -n 's/.*clone=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/ph.out | head -1)
OMAP=$(sed -n 's/.*omap=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/ph.out | head -1)
echo "PID=$PID PAGE=$PAGE replaceA=$RA clone=$CLONE"
echo "-- baseline (A/B/C original) --"; sleep 1; tail -3 $TMP/ph.out

echo "== pagehook: route funcA(entry off 0) -> replaceA, B/C run from clone =="
timeout 15 $C control shpte "pagehook $PID $PAGE $CLONE $OMAP 1024 0 $RA"

echo "== run 3s; funcA hooked (HOOK A + backup), funcB/funcC normal =="
sleep 3
tail -12 $TMP/ph.out
kill -0 "$PID" 2>/dev/null && echo "ALIVE" || echo "DEAD"
timeout 10 $C control shpte dump

echo "== teardown =="
timeout 10 $C control shpte disarm
sleep 1
echo "-- after disarm (A back to normal) --"; tail -3 $TMP/ph.out
timeout 10 $C unload shpte
kill "$PID" 2>/dev/null
echo "== done =="
