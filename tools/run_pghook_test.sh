#!/system/bin/sh
# Multi-page inline hook test (device-side, root). Exercises the KPM multi-page
# table (`pghook` x2 + `pgdisarm`).
#   adb shell su -c 'sh /data/local/tmp/run_pghook_test.sh <APATCH_SUPERKEY>'
# funcA (page P_A) and funcB (page P_B != P_A) each share their page with a
# neighbor. We recompile EACH page and UXN-trap BOTH at once: funcA->replaceA,
# funcB->replaceB, neighbors run from their clones. Proof: A and B both print
# [HOOK ..] + their original body (via backup) while A-nb/B-nb keep printing
# normally -- several page-shared functions on different pages hooked together,
# .text untouched. One `pgdisarm` drops both pages.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_pghook_test.sh <superkey>"; exit 2; }

echo "== load shpte =="
timeout 10 $C control shpte pgdisarm 2>/dev/null
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm
timeout 10 $C control shpte probe

echo "== launch pgtool =="
setsid $TMP/pgtool >$TMP/pg.out 2>&1 </dev/null &
sleep 1
head -3 $TMP/pg.out
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/pg.out | head -1)
PAGEA=$(sed -n 's/.*pageA=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/pg.out | head -1)
CLONEA=$(sed -n 's/.*cloneA=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/pg.out | head -1)
OMAPA=$(sed -n 's/.*omapA=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/pg.out | head -1)
RA=$(sed -n 's/.*replaceA=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/pg.out | head -1)
PAGEB=$(sed -n 's/.*pageB=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/pg.out | head -1)
CLONEB=$(sed -n 's/.*cloneB=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/pg.out | head -1)
OMAPB=$(sed -n 's/.*omapB=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/pg.out | head -1)
RB=$(sed -n 's/.*replaceB=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/pg.out | head -1)
echo "PID=$PID"
echo "  A: page=$PAGEA clone=$CLONEA omap=$OMAPA replace=$RA"
echo "  B: page=$PAGEB clone=$CLONEB omap=$OMAPB replace=$RB"
echo "-- baseline (A/A-nb/B/B-nb original) --"; sleep 1; tail -4 $TMP/pg.out

echo "== pghook page A (funcA entry off 0 -> replaceA) =="
timeout 15 $C control shpte "pghook $PID $PAGEA $CLONEA $OMAPA 1024 0 $RA"
echo "== pghook page B (funcB entry off 0 -> replaceB) =="
timeout 15 $C control shpte "pghook $PID $PAGEB $CLONEB $OMAPB 1024 0 $RB"

echo "== run 3s; A+B hooked (HOOK A/B + backup), neighbors normal =="
sleep 3
tail -24 $TMP/pg.out
kill -0 "$PID" 2>/dev/null && echo "ALIVE" || echo "DEAD"
timeout 10 $C control shpte dump

echo "== teardown (single pgdisarm drops both pages) =="
timeout 10 $C control shpte pgdisarm
sleep 1
echo "-- after pgdisarm (A/B back to normal) --"; tail -8 $TMP/pg.out
timeout 10 $C unload shpte
kill "$PID" 2>/dev/null
echo "== done =="
