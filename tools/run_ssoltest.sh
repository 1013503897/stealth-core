#!/system/bin/sh
# SSOL P1 self-test driver (runs on-device under su).
# Starts ssoltarget, arms shpte SSOL regions on BOTH ssol_add and ssol_mix pages,
# signals it, and reports PASS/FAIL + the simulate/XOL counters per region.
KEY=Lanhuachun2
SHCTL=/data/local/tmp/shctl
TGT=/data/local/tmp/ssoltarget
GO=/data/local/tmp/ssol_go
OUT=/data/local/tmp/ssoltarget.out
XOL_ADD=0x5550000000
XOL_MIX=0x5560000000

rm -f "$GO" "$OUT"
"$TGT" "$GO" > "$OUT" 2>&1 &
TPID=$!
for i in $(seq 1 50); do grep -q '^xol_va=' "$OUT" && break; sleep 0.1; done

PID=$(sed -n 's/^pid=//p' "$OUT")
ADD=$(sed -n 's/^ssol_add=//p' "$OUT")
MIX=$(sed -n 's/^ssol_mix=//p' "$OUT")
echo "[driver] pid=$PID ssol_add=$ADD ssol_mix=$MIX"

echo "[driver] arming ssoltest on ssol_add ..."
timeout 10 "$SHCTL" "$KEY" control shpte "ssoltest $PID $ADD 1 $XOL_ADD"
echo "[driver] arming ssoltest on ssol_mix ..."
timeout 10 "$SHCTL" "$KEY" control shpte "ssoltest $PID $MIX 1 $XOL_MIX"

echo "[driver] signalling target ..."
touch "$GO"

for i in $(seq 1 80); do grep -q '^DONE' "$OUT" && break; sleep 0.1; done
wait "$TPID" 2>/dev/null
TRC=$?

echo "[driver] ===== target output ====="
cat "$OUT"
echo "[driver] ===== ssolstat ====="
timeout 10 "$SHCTL" "$KEY" control shpte ssolstat
echo "[driver] ===== disarm ====="
timeout 10 "$SHCTL" "$KEY" control shpte ssoldisarm
echo "[driver] target_rc=$TRC"
