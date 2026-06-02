#!/system/bin/sh
# P2.2 single-function DBI redirect test (device-side, root).
#   adb shell su -c 'sh /data/local/tmp/run_redirect_test.sh <APATCH_SUPERKEY>'
# dbitarget clones its (page-isolated, PC-relative-free) tick() page into an RX
# mmap. We set UXN on the original tick page and reroute the do_page_fault PC into
# the clone. Proof of redirect (vs P2.1 self-heal): UXN STAYS set, so faults AND
# redirects climb together (every call), yet dbitarget keeps running (calls=...
# advances) -- only possible if execution succeeds from the clone. Always
# disarms + unloads.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_redirect_test.sh <superkey>"; exit 2; }

echo "== ready ==" ; timeout 10 $C ready || { echo "bad key/KP"; exit 1; }
echo "== load shpte =="
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm
timeout 10 $C control shpte probe

echo "== launch dbitarget =="
setsid $TMP/dbitarget >$TMP/dt.out 2>&1 </dev/null &
sleep 1
cat $TMP/dt.out
PID=$(sed -n 's/^pid=\([0-9]*\).*/\1/p' $TMP/dt.out | head -1)
TICK=$(sed -n 's/.*tick=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/dt.out | head -1)
CLONE=$(sed -n 's/.*clone=\(0x[0-9a-fA-F]*\).*/\1/p' $TMP/dt.out | head -1)
echo "PID=$PID TICK=$TICK CLONE=$CLONE"

echo "== PTE before (expect uexec) =="
timeout 10 $C control shpte "pte $PID $TICK"

echo "== REDIRECT tick -> clone =="
timeout 15 $C control shpte "redirect $PID $TICK $CLONE"

echo "== run 3s; tick executes from the clone every call =="
sleep 3
echo "-- target progress: --"; tail -3 $TMP/dt.out
kill -0 "$PID" 2>/dev/null && echo "ALIVE pid=$PID" || echo "DEAD pid=$PID"

echo "== dump (expect mode=REDIRECT, faults~=redirects>1, UXN still set) =="
timeout 10 $C control shpte dump
sleep 2
echo "-- dump again, counts should have grown: --"
timeout 10 $C control shpte dump

echo "== DISARM =="
timeout 10 $C control shpte disarm
sleep 1
kill -0 "$PID" 2>/dev/null && echo "still ALIVE after disarm" || echo "DEAD after disarm"
tail -2 $TMP/dt.out

echo "== unload ==" ; timeout 10 $C unload shpte
echo "== cleanup ==" ; kill "$PID" 2>/dev/null
echo "== done =="
