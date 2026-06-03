#!/system/bin/sh
# P4.1 /proc/maps hide test (device-side, root).
#   adb shell su -c 'sh /data/local/tmp/run_hidemaps_test.sh <APATCH_SUPERKEY>'
# dbitarget mmaps a clone (an RX anon VMA visible in /proc/<pid>/maps). We hook
# show_map and drop the clone's entry. Proof: the clone address is present in
# the target's maps before `hidemaps`, ABSENT after, and present again after
# `unhidemaps` -- with the process still running.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_hidemaps_test.sh <superkey>"; exit 2; }

echo "== load shpte =="
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm
timeout 10 $C control shpte probe | grep -E "show_map"

echo "== launch dbitarget (clone = RX anon vma) =="
setsid $TMP/dbitarget >$TMP/h.out 2>&1 </dev/null &
sleep 1
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/h.out | head -1)
CLONE=$(sed -n 's/.*clone=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/h.out | head -1)
CLONE_BARE=$(echo $CLONE | sed 's/^0x//')
echo "PID=$PID CLONE=$CLONE"

echo "== maps entry BEFORE hide (should show the clone) =="
cat /proc/$PID/maps | grep -i "^$CLONE_BARE" || echo "  (not found?!)"

echo "== hidemaps $CLONE =="
timeout 10 $C control shpte "hidemaps $CLONE"

echo "== maps entry AFTER hide (should be GONE) =="
cat /proc/$PID/maps | grep -i "^$CLONE_BARE" && echo "  STILL VISIBLE (fail)" || echo "  HIDDEN (clone entry absent)"

echo "== dump =="
timeout 10 $C control shpte dump
kill -0 "$PID" 2>/dev/null && echo "reader+target ALIVE" || echo "DEAD"

echo "== unhidemaps (should reappear) =="
timeout 10 $C control shpte unhidemaps
cat /proc/$PID/maps | grep -i "^$CLONE_BARE" >/dev/null && echo "  VISIBLE again (good)" || echo "  still hidden (?)"

echo "== unload =="
timeout 10 $C unload shpte
kill "$PID" 2>/dev/null
echo "== done =="
