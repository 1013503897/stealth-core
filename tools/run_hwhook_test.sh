#!/system/bin/sh
# HWBP-redirect inline_hooker test on a NON-page-isolated target (device-side, root).
#   adb shell su -c 'sh /data/local/tmp/run_hwhook_test.sh <APATCH_SUPERKEY>'
# victimA/victimB share a page. hwhookto victimA->replaceA via a hardware breakpoint.
# Proof: after hook, victimA -> [R] replaced + [A] orig (ghost backup), while
# victimB keeps printing [B] normally (page-neighbor untouched, unlike UXN-per-page).
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_hwhook_test.sh <superkey>"; exit 2; }

echo "== load shpte =="
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm

echo "== launch hwhooktool =="
setsid $TMP/hwhooktool >$TMP/hw.out 2>&1 </dev/null &
sleep 1
head -1 $TMP/hw.out
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/hw.out | head -1)
A=$(sed -n 's/.*victimA=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/hw.out | head -1)
R=$(sed -n 's/.*replaceA=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/hw.out | head -1)
CB=$(sed -n 's/.*clonebuf=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/hw.out | head -1)
NC=$(sed -n 's/.*nclone=\([0-9]*\).*/\1/p' $TMP/hw.out | head -1)
TV=$(sed -n 's/.*template_va=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/hw.out | head -1)
GV=$(sed -n 's/.*ghost_va=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/hw.out | head -1)
echo "PID=$PID victimA=$A replaceA=$R nclone=$NC ghost=$GV"
echo "-- baseline ([A] and [B] both orig) --"; sleep 1; tail -3 $TMP/hw.out

echo "== hwhookto victimA -> replaceA (hardware breakpoint) =="
timeout 15 $C control shpte "hwhookto $PID $A $R $CB $NC $TV $GV"

echo "== run 3s; expect [R] replaced + [A] orig for A, and [B] STILL orig =="
sleep 3
tail -9 $TMP/hw.out
kill -0 "$PID" 2>/dev/null && echo "ALIVE" || echo "DEAD (bug)"
echo "== dump =="; timeout 10 $C control shpte dump

echo "== teardown: hwunhook + ghostfree =="
timeout 10 $C control shpte hwunhook
sleep 1
timeout 10 $C control shpte ghostfree
sleep 1
echo "-- after teardown (A back to orig) --"; tail -3 $TMP/hw.out
kill -0 "$PID" 2>/dev/null && echo "still ALIVE" || echo "DEAD after teardown"

echo "== unload =="; timeout 10 $C unload shpte
kill "$PID" 2>/dev/null
echo "== done =="
