#!/system/bin/sh
# P3.4 DBI redirect test for LDR-literal.
#   adb shell su -c 'sh /data/local/tmp/run_dbi4_test.sh <APATCH_SUPERKEY>'
# dbitarget4 recompiles lwork() -- which loads a 64-bit constant via an LDR from a
# PC-relative literal pool -- re-pointing the load to a clone-local copy of the
# value. We UXN-trap lwork()'s page and route into the clone. Proof: after
# redirect, output stays correct (lwork(i)=0x123456789abcdef0+i) from the
# UXN-trapped original, i.e. the LDR-literal (and ADR/BL) were recompiled right.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_dbi4_test.sh <superkey>"; exit 2; }

echo "== load shpte =="
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm

echo "== launch dbitarget4 =="
setsid $TMP/dbitarget4 >$TMP/d4.out 2>&1 </dev/null &
sleep 1
head -1 $TMP/d4.out
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/d4.out | head -1)
FN=$(sed -n 's/.*lwork=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/d4.out | head -1)
CLONE=$(sed -n 's/.*clone=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/d4.out | head -1)
OMAP=$(sed -n 's/.*omap=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/d4.out | head -1)
echo "PID=$PID lwork=$FN CLONE=$CLONE OMAP=$OMAP"
echo "-- baseline (original lwork) --"; sleep 1; tail -2 $TMP/d4.out

echo "== redirectmap lwork -> DBI clone =="
timeout 15 $C control shpte "redirectmap $PID $FN $CLONE $OMAP 1024"

echo "== run 3s; values must stay correct (0x123456789abcdef0 + i) =="
sleep 3
echo "-- output after redirect --"; tail -5 $TMP/d4.out
kill -0 "$PID" 2>/dev/null && echo "ALIVE pid=$PID" || echo "DEAD pid=$PID (DBI bug)"
timeout 10 $C control shpte dump

echo "== disarm/unload =="
timeout 10 $C control shpte disarm
timeout 10 $C unload shpte
kill "$PID" 2>/dev/null
echo "== done =="
