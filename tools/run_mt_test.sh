#!/system/bin/sh
# P1.6 multi-thread-following test harness (device-side, run as root).
#   adb shell su -c 'sh /data/local/tmp/run_mt_test.sh <APATCH_SUPERKEY>'
# Loads shhwbp.kpm, launches mttarget, enumerates its threads from
# /proc/<pid>/task, installs a per-thread HWBP on tick() for every thread, and
# verifies each thread independently records entry+return hits. All supercalls
# are wrapped in `timeout`; unhook always precedes unload.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_mt_test.sh <superkey>"; exit 2; }

echo "== ready =="
timeout 10 $C ready || { echo "bad superkey / KP not responding"; exit 1; }

echo "== load shhwbp =="
timeout 10 $C unload shhwbp 2>/dev/null
timeout 10 $C load $TMP/shhwbp.kpm

echo "== probe =="
timeout 10 $C control shhwbp probe

echo "== launch mttarget =="
setsid $TMP/mttarget >$TMP/mt.out 2>&1 </dev/null &
sleep 1
cat $TMP/mt.out
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/mt.out | head -1)
TICK=$(sed -n 's/.*tick=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/mt.out | head -1)
TIDS=$(ls /proc/$PID/task 2>/dev/null | tr '\n' ' ')
echo "parsed: PID=$PID TICK=$TICK TIDS=[$TIDS]"

echo "== hook all threads =="
timeout 10 $C control shhwbp "hook $TICK $PID $TIDS"

echo "== let it run 3s, then dump =="
sleep 3
timeout 10 $C control shhwbp dump

echo "== unhook =="
timeout 10 $C control shhwbp unhook
sleep 1
echo "== dump after unhook =="
timeout 10 $C control shhwbp dump

echo "== unload =="
timeout 10 $C unload shhwbp

echo "== cleanup target (pid=$PID) =="
kill "$PID" 2>/dev/null
echo "== done =="
