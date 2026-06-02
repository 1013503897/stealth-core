#!/system/bin/sh
# P2.1 UXN + do_page_fault self-heal test (device-side, root).
#   adb shell su -c 'sh /data/local/tmp/run_uxn_test.sh <APATCH_SUPERKEY>'
# Sets UXN on mttarget's tick() code page, hooks do_page_fault; each EL0 execute
# of tick faults and the handler self-heals (clears UXN, re-executes). Verifies:
# the fault was intercepted (faults>=1), the target keeps running (no crash), and
# the device survives (no brick). Always disarms + unloads, even on the way out.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_uxn_test.sh <superkey>"; exit 2; }

echo "== ready ==" ; timeout 10 $C ready || { echo "bad key/KP"; exit 1; }
echo "== load shpte =="
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm
timeout 10 $C control shpte probe

echo "== launch mttarget =="
setsid $TMP/mttarget grow >$TMP/up.out 2>&1 </dev/null &
sleep 1
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/up.out | head -1)
TICK=$(sed -n 's/.*tick=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/up.out | head -1)
echo "PID=$PID TICK=$TICK"

echo "== PTE before arm (expect uexec, UXN clear) =="
timeout 10 $C control shpte "pte $PID $TICK"

echo "== ARM (set UXN + hook do_page_fault) =="
timeout 15 $C control shpte "arm $PID $TICK"

echo "== let it run 3s (threads execute tick -> fault -> self-heal) =="
sleep 3
echo "-- target progress (tail of its output): --"
tail -3 $TMP/up.out
echo "-- is target alive? --"
kill -0 "$PID" 2>/dev/null && echo "ALIVE pid=$PID" || echo "DEAD pid=$PID"

echo "== dump (expect faults>=1, pte_now self-healed to uexec) =="
timeout 10 $C control shpte dump

echo "== DISARM =="
timeout 10 $C control shpte disarm
sleep 1
kill -0 "$PID" 2>/dev/null && echo "still ALIVE after disarm" || echo "DEAD after disarm"

echo "== unload =="
timeout 10 $C unload shpte
echo "== cleanup ==" ; kill "$PID" 2>/dev/null
echo "== done =="
