#!/system/bin/sh
# P1.6b/B2 thread-exit GC test (device-side, run as root).
#   adb shell su -c 'sh /data/local/tmp/run_churn_test.sh <APATCH_SUPERKEY>'
# Launches mttarget in churn mode: it keeps spawning workers that each exit after
# a few ticks. With do_exit GC armed, slots for exited threads must be retired
# (auto_removed grows, slot_count stays bounded, no leak/crash). Verifies the
# create+exit cycle is stable over many rounds, then unhook/unload cleanly.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_churn_test.sh <superkey>"; exit 2; }

echo "== ready ==" ; timeout 10 $C ready || { echo "bad key/KP"; exit 1; }

echo "== load shhwbp =="
timeout 10 $C unload shhwbp 2>/dev/null
timeout 10 $C load $TMP/shhwbp.kpm
timeout 10 $C control shhwbp probe

echo "== launch mttarget (churn) =="
setsid $TMP/mttarget churn >$TMP/mt.out 2>&1 </dev/null &
sleep 1
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/mt.out | head -1)
TICK=$(sed -n 's/.*tick=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/mt.out | head -1)
TIDS0=$(ls /proc/$PID/task 2>/dev/null | tr '\n' ' ')
echo "t0: PID=$PID TICK=$TICK initial=[$TIDS0]"

echo "== hook + arm follow/gc on tgid=$PID =="
timeout 10 $C control shhwbp "hook $TICK $PID $TIDS0"

# Sample the table several times across ~24s of create/exit churn.
i=0
while [ $i -lt 6 ]; do
    sleep 4
    echo "--- sample $i (live threads: $(ls /proc/$PID/task 2>/dev/null | wc -l)) ---"
    timeout 10 $C control shhwbp dump
    i=$((i + 1))
done

echo "== unhook =="
timeout 10 $C control shhwbp unhook
sleep 1
timeout 10 $C control shhwbp dump
echo "== unload ==" ; timeout 10 $C unload shhwbp
echo "== cleanup (pid=$PID) ==" ; kill "$PID" 2>/dev/null
echo "== done =="
