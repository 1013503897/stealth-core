#!/system/bin/sh
# P4.2 step A: VMA-less ghost-memory injection test (device-side, root).
#   adb shell su -c 'sh /data/local/tmp/run_ghost_test.sh <APATCH_SUPERKEY>'
# Inject a kernel page at ghosttool's chosen no-VMA VA; the tool then reads the
# magic from it while mincore/maps say it isn't mapped. ghostfree always runs.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_ghost_test.sh <superkey>"; exit 2; }

echo "== load shpte =="
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm
timeout 10 $C control shpte probe | grep -E "apply_to_page_range|__get_free_pages"

echo "== launch ghosttool =="
setsid $TMP/ghosttool >$TMP/g.out 2>&1 </dev/null &
sleep 1
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/g.out | head -1)
GVA=$(sed -n 's/.*ghost_va=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/g.out | head -1)
TVA=$(sed -n 's/.*template_va=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/g.out | head -1)
echo "PID=$PID GHOST_VA=$GVA TEMPLATE_VA=$TVA"
echo "-- before inject (expect 'read faulted') --"; sleep 1; tail -2 $TMP/g.out

echo "== ghosttest (inject PTE at the no-VMA VA) =="
timeout 15 $C control shpte "ghosttest $PID $GVA $TVA"

echo "== after inject: tool should READ the magic, mincore<0, in_maps=0 =="
sleep 2
tail -3 $TMP/g.out
kill -0 "$PID" 2>/dev/null && echo "tool ALIVE" || echo "tool DEAD"
echo "== cross-check: grep ghost VA in the tool's maps (should be empty) =="
GBARE=$(echo $GVA | sed 's/^0x//')
cat /proc/$PID/maps | grep -iE "^$GBARE-" && echo "  VISIBLE in maps (fail)" || echo "  not in maps (good)"

echo "== ghostfree =="
timeout 10 $C control shpte ghostfree
sleep 1
echo "-- after free (expect 'read faulted' again) --"; tail -2 $TMP/g.out

echo "== unload =="
timeout 10 $C unload shpte
kill "$PID" 2>/dev/null
echo "== done =="
