#!/system/bin/sh
# inline_hooker primitive test (device-side, root).
#   adb shell su -c 'sh /data/local/tmp/run_hookto_test.sh <APATCH_SUPERKEY>'
# hookto reroutes funcA -> funcB (replace) and stashes a ghost clone of funcA as
# the backup. Proof: after hookto, each funcA(i) call prints
#   [B] hooked .. / [A] orig .. (from the ghost backup) / [B] done ..
# while funcA's .text is UXN-trapped and the backup lives in VMA-less memory.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_hookto_test.sh <superkey>"; exit 2; }

echo "== load shpte =="
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm

echo "== launch hooktool =="
setsid $TMP/hooktool >$TMP/hk.out 2>&1 </dev/null &
sleep 1
head -1 $TMP/hk.out
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/hk.out | head -1)
A=$(sed -n 's/.*funcA=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/hk.out | head -1)
B=$(sed -n 's/.*funcB=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/hk.out | head -1)
CB=$(sed -n 's/.*clonebuf=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/hk.out | head -1)
NC=$(sed -n 's/.*nclone=\([0-9]*\).*/\1/p' $TMP/hk.out | head -1)
TV=$(sed -n 's/.*template_va=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/hk.out | head -1)
GV=$(sed -n 's/.*ghost_va=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/hk.out | head -1)
echo "PID=$PID funcA=$A funcB=$B clonebuf=$CB nclone=$NC template=$TV ghost=$GV"
echo "-- baseline (only [A] orig) --"; sleep 1; tail -2 $TMP/hk.out

echo "== hookto funcA -> funcB (backup = ghost clone of funcA) =="
timeout 15 $C control shpte "hookto $PID $A $B $CB $NC $TV $GV"

echo "== run 3s; expect [B] hooked / [A] orig / [B] done per call =="
sleep 3
tail -7 $TMP/hk.out
kill -0 "$PID" 2>/dev/null && echo "ALIVE" || echo "DEAD (bug)"
echo "== dump =="; timeout 10 $C control shpte dump

echo "== teardown: disarm + ghostfree =="
timeout 10 $C control shpte disarm
timeout 10 $C control shpte ghostfree
sleep 1
echo "-- after teardown (back to [A] orig) --"; tail -2 $TMP/hk.out
kill -0 "$PID" 2>/dev/null && echo "still ALIVE" || echo "DEAD after teardown"

echo "== unload =="; timeout 10 $C unload shpte
kill "$PID" 2>/dev/null
echo "== done =="
