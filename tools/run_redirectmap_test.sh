#!/system/bin/sh
# P3.1 offset_map routing test (device-side, root).
#   adb shell su -c 'sh /data/local/tmp/run_redirectmap_test.sh <APATCH_SUPERKEY>'
# Same as the P2.2 redirect, but routes via an offset_map read from the target's
# user memory with access_process_vm. dbitarget ships an IDENTITY map, so this
# must reproduce P2.2 exactly (faults==redirects climb, target stays alive) --
# validating the map plumbing before the real DBI engine fills a non-identity map.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_redirectmap_test.sh <superkey>"; exit 2; }

echo "== load shpte =="
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm
timeout 10 $C control shpte probe

echo "== launch dbitarget =="
setsid $TMP/dbitarget >$TMP/dt.out 2>&1 </dev/null &
sleep 1
cat $TMP/dt.out
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/dt.out | head -1)
TICK=$(sed -n 's/.*tick=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/dt.out | head -1)
CLONE=$(sed -n 's/.*clone=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/dt.out | head -1)
OMAP=$(sed -n 's/.*omap=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/dt.out | head -1)
echo "PID=$PID TICK=$TICK CLONE=$CLONE OMAP=$OMAP"

echo "== redirectmap (identity offset_map, 1024 entries) =="
timeout 15 $C control shpte "redirectmap $PID $TICK $CLONE $OMAP 1024"

echo "== run 3s =="
sleep 3
tail -2 $TMP/dt.out
kill -0 "$PID" 2>/dev/null && echo "ALIVE pid=$PID" || echo "DEAD pid=$PID"
echo "== dump (expect mode=REDIRECT_MAP nmap=1024, faults~=redirects>1) =="
timeout 10 $C control shpte dump

echo "== disarm/unload =="
timeout 10 $C control shpte disarm
timeout 10 $C unload shpte
kill "$PID" 2>/dev/null
echo "== done =="
