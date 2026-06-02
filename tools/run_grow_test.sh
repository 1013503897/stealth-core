#!/system/bin/sh
# P1.6b/B1 new-thread-following test (device-side, run as root).
#   adb shell su -c 'sh /data/local/tmp/run_grow_test.sh <APATCH_SUPERKEY>'
# Launches mttarget (grow), hooks ONLY the threads that exist at t0 and arms
# new-thread following on the tgid, then waits while mttarget spawns more workers
# and verifies they get auto-followed (slots grow, auto_added>0). Unhook precedes
# unload; all supercalls are timeout-wrapped.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_grow_test.sh <superkey>"; exit 2; }

echo "== ready =="
timeout 10 $C ready || { echo "bad superkey / KP not responding"; exit 1; }

echo "== load shhwbp =="
timeout 10 $C unload shhwbp 2>/dev/null
timeout 10 $C load $TMP/shhwbp.kpm

echo "== probe =="
timeout 10 $C control shhwbp probe

echo "== launch mttarget (grow) =="
setsid $TMP/mttarget grow >$TMP/mt.out 2>&1 </dev/null &
sleep 1
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/mt.out | head -1)
TICK=$(sed -n 's/.*tick=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/mt.out | head -1)
TIDS0=$(ls /proc/$PID/task 2>/dev/null | tr '\n' ' ')
echo "t0: PID=$PID TICK=$TICK initial-threads=[$TIDS0]"

echo "== hook initial threads + arm follow-new on tgid=$PID =="
timeout 10 $C control shhwbp "hook $TICK $PID $TIDS0"
timeout 10 $C control shhwbp dump

echo "== wait 14s for mttarget to spawn more workers (auto-follow) =="
sleep 14
echo "threads now: [$(ls /proc/$PID/task 2>/dev/null | tr '\n' ' ')]"
echo "(dump: * marks auto-followed threads)"
timeout 10 $C control shhwbp dump

echo "== unhook =="
timeout 10 $C control shhwbp unhook
sleep 1
timeout 10 $C control shhwbp dump

echo "== unload =="
timeout 10 $C unload shhwbp
echo "== cleanup (pid=$PID) =="
kill "$PID" 2>/dev/null
echo "== mttarget thread log =="
cat $TMP/mt.out
echo "== done =="
