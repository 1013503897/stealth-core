#!/system/bin/sh
# P4.2 step B: execute the DBI clone from VMA-less ghost memory (device-side, root).
#   adb shell su -c 'sh /data/local/tmp/run_ghostexec_test.sh <APATCH_SUPERKEY>'
# The KPM copies ghostexec's recompiled hook_me clone into a no-VMA ghost page and
# redirects the UXN-trapped hook_me there. Proof: "[ghost] hook_me n=K" output
# continues correctly (runs from the clone) while the original .text is UXN-trapped
# AND the ghost VA is absent from /proc/maps -- a hook with no .text change and no
# discoverable executable mapping.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_ghostexec_test.sh <superkey>"; exit 2; }

echo "== load shpte =="
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm

echo "== launch ghostexec =="
setsid $TMP/ghostexec >$TMP/ge.out 2>&1 </dev/null &
sleep 1
head -1 $TMP/ge.out
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/ge.out | head -1)
FN=$(sed -n 's/.*hook_me=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/ge.out | head -1)
CB=$(sed -n 's/.*clonebuf=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/ge.out | head -1)
NC=$(sed -n 's/.*nclone=\([0-9]*\).*/\1/p' $TMP/ge.out | head -1)
OMAP=$(sed -n 's/.*omap=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/ge.out | head -1)
GVA=$(sed -n 's/.*ghost_va=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/ge.out | head -1)
TVA=$(sed -n 's/.*template_va=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/ge.out | head -1)
echo "PID=$PID hook_me=$FN clonebuf=$CB nclone=$NC ghost_va=$GVA template=$TVA"
echo "-- baseline (original) --"; sleep 1; tail -2 $TMP/ge.out

echo "== ghostredirect (clone -> ghost page, redirect hook_me there) =="
timeout 15 $C control shpte "ghostredirect $PID $FN $GVA $CB $NC $OMAP 1024 $TVA"

echo "== run 3s; output must come from the clone in ghost memory =="
sleep 3
tail -4 $TMP/ge.out
kill -0 "$PID" 2>/dev/null && echo "ALIVE" || echo "DEAD (bug)"
echo "== dump =="; timeout 10 $C control shpte dump
echo "== is the ghost VA in maps? (should be absent) =="
GBARE=$(echo $GVA | sed 's/^0x//')
cat /proc/$PID/maps | grep -iE "^$GBARE-" && echo "  VISIBLE (fail)" || echo "  not in maps (ghost)"

echo "== teardown: disarm + ghostfree =="
timeout 10 $C control shpte disarm
timeout 10 $C control shpte ghostfree
sleep 1
tail -2 $TMP/ge.out
kill -0 "$PID" 2>/dev/null && echo "still ALIVE after teardown" || echo "DEAD after teardown"

echo "== unload =="; timeout 10 $C unload shpte
kill "$PID" 2>/dev/null
echo "== done =="
