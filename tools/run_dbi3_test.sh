#!/system/bin/sh
# P3.3 DBI redirect test for a function with a LOOP (internal branches).
#   adb shell su -c 'sh /data/local/tmp/run_dbi3_test.sh <APATCH_SUPERKEY>'
# dbitarget3 recompiles work() -- which has internal B.cond (b.lt/b.ne) + an
# internal B + external ADR/BL -- into a clone with internal branches re-encoded
# clone-relative. We UXN-trap work()'s page and route the entry fault into the
# clone. Proof: after redirect, work()'s output keeps producing the SAME correct
# results (work(2)=1 work(3)=10 work(4)=83 work(5)=668 work(6)=5349) from the
# UXN-trapped (un-runnable) original -- i.e. the loop, conditional branches, ADR
# and BL were all recompiled correctly.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_dbi3_test.sh <superkey>"; exit 2; }

echo "== load shpte =="
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm

echo "== launch dbitarget3 =="
setsid $TMP/dbitarget3 >$TMP/d3.out 2>&1 </dev/null &
sleep 1
head -1 $TMP/d3.out
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/d3.out | head -1)
FN=$(sed -n 's/.*work=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/d3.out | head -1)
CLONE=$(sed -n 's/.*clone=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/d3.out | head -1)
OMAP=$(sed -n 's/.*omap=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/d3.out | head -1)
echo "PID=$PID work=$FN CLONE=$CLONE OMAP=$OMAP"
echo "-- baseline (original work) --"; sleep 1; tail -3 $TMP/d3.out

echo "== redirectmap work -> DBI clone =="
timeout 15 $C control shpte "redirectmap $PID $FN $CLONE $OMAP 1024"

echo "== run 4s; results must stay correct, computed from the clone =="
sleep 4
echo "-- output after redirect --"; tail -8 $TMP/d3.out
kill -0 "$PID" 2>/dev/null && echo "ALIVE pid=$PID" || echo "DEAD pid=$PID (DBI bug)"
timeout 10 $C control shpte dump

echo "== disarm/unload =="
timeout 10 $C control shpte disarm
timeout 10 $C unload shpte
kill "$PID" 2>/dev/null
echo "== done =="
