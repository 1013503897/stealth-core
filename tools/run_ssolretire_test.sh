#!/system/bin/sh
# Prove the staleness guard RETIRES a stale hooked-entry override on drift-at-entry
# (the method-moved case). Arm an ssolhook override on hook_me, set enforce, poison
# hook_me's ENTRY word (== drift at the hooked offset), then call hook_me:
#   guard refreshes from live + retires ov0 -> hook_me runs UN-HOOKED (returns 7, not
#   1007 via tramp), nov goes 1->0, no crash, no wrong-redirect.
# Contrast: without poison the same hook returns 1007 (redirected to tramp).
KEY=Lanhuachun2
SHCTL=/data/local/tmp/shctl
TGT=/data/local/tmp/ssoltarget
GO=/data/local/tmp/ssol_go
OUT=/data/local/tmp/ssoltarget.out
XOL_HOOK=0x5580000000
BK1=0x5590000000
POISON="${1:-0x0}"   # 0x0 = poison entry (retire);  none = control (stays hooked=1007)

am force-stop com.android.hookdemo 2>/dev/null
$SHCTL $KEY control shpte ssoldisarm >/dev/null 2>&1
$SHCTL $KEY control shpte ssolgc >/dev/null 2>&1

rm -f "$GO" "$OUT"
"$TGT" "$GO" > "$OUT" 2>&1 &
TPID=$!
for i in $(seq 1 50); do grep -q '^xol_va=' "$OUT" && break; sleep 0.1; done
PID=$(sed -n 's/^pid=//p' "$OUT")
HM=$(sed -n 's/^hook_me=//p' "$OUT")
TR=$(sed -n 's/^tramp=//p' "$OUT")
echo "[r] pid=$PID hook_me=$HM tramp=$TR poison=$POISON guard=enforce"

echo "[r] arm ssolhook ov0 on hook_me (replace=tramp bk=$BK1)"
$SHCTL $KEY control shpte "ssolhook $PID $HM 1 $XOL_HOOK $HM $TR $BK1"
SLOT=$($SHCTL $KEY control shpte ssolstat | grep "pid=$PID" | sed -n 's/.*ssol\[\([0-9]*\)\].*/\1/p' | head -1)
[ -z "$SLOT" ] && SLOT=0
echo "[r] hook armed in slot=$SLOT"

$SHCTL $KEY control shpte "ssolguard 2" >/dev/null
if [ "$POISON" != "none" ]; then
  echo "[r] poison slot=$SLOT woff=0 (hook_me entry) val=$POISON"
  $SHCTL $KEY control shpte "ssolpoison $SLOT 0 $POISON"
fi

echo "[r] GO"
touch "$GO"
for i in $(seq 1 80); do grep -q '^DONE' "$OUT" && break; grep -q 'TIMEOUT' "$OUT" && break; sleep 0.1; done
sleep 0.3

echo "[r] ===== ssolstat (expect nov 1->0 if retired; drift/refresh up) ====="
$SHCTL $KEY control shpte ssolstat | grep -E "guard=|pid=$PID"
echo "[r] ===== hook_me result ====="
grep '^hook_me(' "$OUT" || echo "  (no hook_me line -> crashed?)"
wait "$TPID" 2>/dev/null; echo "[r] target_rc=$?"
