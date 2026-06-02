#!/system/bin/sh
# P3.2 DBI redirect test (device-side, root).
#   adb shell su -c 'sh /data/local/tmp/run_dbi_test.sh <APATCH_SUPERKEY>'
# dbitarget2 recompiles its PC-relative hook_me() (ADR+B) into a clone and builds
# an offset_map. We UXN-trap hook_me's page and route the fault into the clone.
# Proof: hook_me's original .text is UXN-trapped (can't run), so every
# "[clone] hook_me n=K" line printed AFTER redirect comes from the DBI-recompiled
# clone -- i.e. the ADR (string ptr) and B (printf tail call) fixups are correct.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_dbi_test.sh <superkey>"; exit 2; }

echo "== load shpte =="
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm

echo "== launch dbitarget2 (recompiles hook_me at startup) =="
setsid $TMP/dbitarget2 >$TMP/d2.out 2>&1 </dev/null &
sleep 1
head -1 $TMP/d2.out
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/d2.out | head -1)
HM=$(sed -n 's/.*hook_me=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/d2.out | head -1)
PAGE=$(sed -n 's/.*page=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/d2.out | head -1)
CLONE=$(sed -n 's/.*clone=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/d2.out | head -1)
OMAP=$(sed -n 's/.*omap=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/d2.out | head -1)
echo "PID=$PID HOOK_ME=$HM PAGE=$PAGE CLONE=$CLONE OMAP=$OMAP"
echo "-- baseline output (original hook_me running): --"
sleep 1; tail -2 $TMP/d2.out

echo "== redirectmap hook_me -> DBI clone =="
timeout 15 $C control shpte "redirectmap $PID $HM $CLONE $OMAP 1024"

echo "== run 3s; output now MUST come from the recompiled clone =="
sleep 3
echo "-- output after redirect: --"; tail -4 $TMP/d2.out
kill -0 "$PID" 2>/dev/null && echo "ALIVE pid=$PID" || echo "DEAD pid=$PID (DBI bug -> crash)"

echo "== dump =="
timeout 10 $C control shpte dump

echo "== disarm/unload =="
timeout 10 $C control shpte disarm
timeout 10 $C unload shpte
echo "-- final output lines: --"; tail -2 $TMP/d2.out
kill "$PID" 2>/dev/null
echo "== done =="
