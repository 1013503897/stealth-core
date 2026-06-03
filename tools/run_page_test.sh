#!/system/bin/sh
# Whole-page DBI test (device-side, root).
#   adb shell su -c 'sh /data/local/tmp/run_page_test.sh <APATCH_SUPERKEY>'
# funcA/funcB/funcC share a page; we recompile the whole page and route it to the
# clone. After redirectmap (UXN the page), all three must keep printing correct
# results -- proving every function on the page runs from the clone while the
# original page is UXN-trapped (the basis for process-wide UXN hooking).
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_page_test.sh <superkey>"; exit 2; }

echo "== load shpte =="
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm

echo "== launch pagetool =="
setsid $TMP/pagetool >$TMP/pg.out 2>&1 </dev/null &
sleep 1
head -1 $TMP/pg.out
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/pg.out | head -1)
PAGE=$(sed -n 's/.*page=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/pg.out | head -1)
CLONE=$(sed -n 's/.*clone=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/pg.out | head -1)
OMAP=$(sed -n 's/.*omap=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/pg.out | head -1)
SAME=$(sed -n 's/.*same_page=\([0-9]*\).*/\1/p' $TMP/pg.out | head -1)
NINS=$(sed -n 's/.*clone_insns=\([0-9]*\).*/\1/p' $TMP/pg.out | head -1)
echo "PID=$PID PAGE=$PAGE same_page=$SAME clone=$CLONE clone_insns=$NINS"
echo "-- baseline (A/B/C from original) --"; sleep 1; tail -3 $TMP/pg.out

echo "== redirectmap whole page -> clone =="
timeout 15 $C control shpte "redirectmap $PID $PAGE $CLONE $OMAP 1024"

echo "== run 3s; A/B/C must all stay correct (now running from the clone) =="
sleep 3
tail -9 $TMP/pg.out
kill -0 "$PID" 2>/dev/null && echo "ALIVE" || echo "DEAD (whole-page DBI bug)"
echo "== dump =="; timeout 10 $C control shpte dump

echo "== teardown =="
timeout 10 $C control shpte disarm
sleep 1
tail -3 $TMP/pg.out
kill -0 "$PID" 2>/dev/null && echo "still ALIVE" || echo "DEAD after disarm"
timeout 10 $C unload shpte
kill "$PID" 2>/dev/null
echo "== done =="
