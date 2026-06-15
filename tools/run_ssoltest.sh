#!/system/bin/sh
# SSOL self-test driver (runs on-device under su).
# Starts ssoltarget, arms shpte SSOL regions on the pass-through test funcs
# (ssol_add/ssol_mix/ssol_indirect) AND a single multi-ov hook region covering
# hook_me + hook_me2 (two overrides {tramp,bk_va} on ONE trapped page), signals the
# target, reports PASS/FAIL + the simulate/XOL/hook/orig counters, then exercises
# ssolunhook (remove ov1, then ov0 -> region disarms) while the target is still alive.
KEY=Lanhuachun2
SHCTL=/data/local/tmp/shctl
TGT=/data/local/tmp/ssoltarget
GO=/data/local/tmp/ssol_go
OUT=/data/local/tmp/ssoltarget.out
XOL_ADD=0x5550000000
XOL_MIX=0x5560000000
XOL_IND=0x5570000000
XOL_HOOK=0x5580000000
BK1=0x5590000000
BK2=0x5591000000

rm -f "$GO" "$OUT"
"$TGT" "$GO" > "$OUT" 2>&1 &
TPID=$!
for i in $(seq 1 50); do grep -q '^xol_va=' "$OUT" && break; sleep 0.1; done

PID=$(sed -n 's/^pid=//p' "$OUT")
ADD=$(sed -n 's/^ssol_add=//p' "$OUT")
MIX=$(sed -n 's/^ssol_mix=//p' "$OUT")
IND=$(sed -n 's/^ssol_indirect=//p' "$OUT")
HM=$(sed -n 's/^hook_me=//p' "$OUT")
HM2=$(sed -n 's/^hook_me2=//p' "$OUT")
TR=$(sed -n 's/^tramp=//p' "$OUT")
TR2=$(sed -n 's/^tramp2=//p' "$OUT")
SP=$(sed -n 's/^hm_hm2_same_page=//p' "$OUT")
echo "[driver] pid=$PID add=$ADD mix=$MIX ind=$IND"
echo "[driver] hook_me=$HM hook_me2=$HM2 tramp=$TR tramp2=$TR2 same_page=$SP"
[ "$SP" = "1" ] || echo "[driver] WARNING: hook_me/hook_me2 NOT co-page -> multi-ov test invalid"

echo "[driver] arming ssoltest on ssol_add ..."
timeout 10 "$SHCTL" "$KEY" control shpte "ssoltest $PID $ADD 1 $XOL_ADD"
echo "[driver] arming ssoltest on ssol_mix ..."
timeout 10 "$SHCTL" "$KEY" control shpte "ssoltest $PID $MIX 1 $XOL_MIX"
echo "[driver] arming ssoltest on ssol_indirect ..."
timeout 10 "$SHCTL" "$KEY" control shpte "ssoltest $PID $IND 1 $XOL_IND"
# ONE region (base=hook_me's page, npages=1) hosting TWO overrides:
echo "[driver] arming ssolhook ov0 hook_me  (base=$HM replace=$TR  bk=$BK1) ..."
timeout 10 "$SHCTL" "$KEY" control shpte "ssolhook $PID $HM 1 $XOL_HOOK $HM $TR $BK1"
echo "[driver] arming ssolhook ov1 hook_me2 (append, replace=$TR2 bk=$BK2) ..."
timeout 10 "$SHCTL" "$KEY" control shpte "ssolhook $PID $HM 1 $XOL_HOOK $HM2 $TR2 $BK2"

echo "[driver] signalling target ..."
touch "$GO"

# target prints DONE then lingers ~3s -> unhook while it is ALIVE
for i in $(seq 1 80); do grep -q '^DONE' "$OUT" && break; sleep 0.1; done

echo "[driver] ===== ssolstat (hooks live) ====="
timeout 10 "$SHCTL" "$KEY" control shpte ssolstat
echo "[driver] ===== ssolunhook ov1 hook_me2 (region stays armed) ====="
timeout 10 "$SHCTL" "$KEY" control shpte "ssolunhook $PID $HM $HM2"
echo "[driver] ===== ssolunhook ov0 hook_me (last ov -> disarm region) ====="
timeout 10 "$SHCTL" "$KEY" control shpte "ssolunhook $PID $HM $HM"

wait "$TPID" 2>/dev/null
TRC=$?

echo "[driver] ===== target output ====="
cat "$OUT"
echo "[driver] ===== ssolstat (after hook-region unhook) ====="
timeout 10 "$SHCTL" "$KEY" control shpte ssolstat
echo "[driver] ===== disarm (remaining pass-through regions) ====="
timeout 10 "$SHCTL" "$KEY" control shpte ssoldisarm
echo "[driver] target_rc=$TRC"
