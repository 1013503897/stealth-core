#!/system/bin/sh
# Deterministic SSOL snapshot-staleness guard test (P3 5.6).
#
# Arms an SSOL pass-through region on ssoltarget's ssol_add, optionally POISONS the
# snapshot's entry word so live != snapshot at the next fault (logically identical to
# ART recycling the trapped page: the snapshot mis-describes the live bytes), sets the
# guard mode, then lets the target call ssol_add(3,4).
#
#   guard=observe + poison 0 (UDF) -> executes the stale snapshot -> SIGILL   [the bug]
#   guard=enforce + poison 0 (UDF) -> refreshes snapshot from live -> r1=7    [the fix]
#   guard=observe + no poison      -> r1=7, drift=0 (live==snapshot)          [no false positive]
#
# Usage: run_ssolguard_test.sh <mode 0|1|2> <poison_hex|none>
KEY=Lanhuachun2
SHCTL=/data/local/tmp/shctl
TGT=/data/local/tmp/ssoltarget
GO=/data/local/tmp/ssol_go
OUT=/data/local/tmp/ssoltarget.out
XOL_ADD=0x5550000000
MODE="${1:-1}"
POISON="${2:-none}"

# clean slate: drop any stale regions, stop the in-app probe target
am force-stop com.android.hookdemo 2>/dev/null
$SHCTL $KEY control shpte ssoldisarm >/dev/null 2>&1
$SHCTL $KEY control shpte ssolgc >/dev/null 2>&1

rm -f "$GO" "$OUT"
"$TGT" "$GO" > "$OUT" 2>&1 &
TPID=$!
for i in $(seq 1 50); do grep -q '^xol_va=' "$OUT" && break; sleep 0.1; done
PID=$(sed -n 's/^pid=//p' "$OUT")
ADD=$(sed -n 's/^ssol_add=//p' "$OUT")
echo "[g] pid=$PID ssol_add=$ADD mode=$MODE poison=$POISON"

echo "[g] arm ssoltest on ssol_add"
$SHCTL $KEY control shpte "ssoltest $PID $ADD 1 $XOL_ADD"

SLOT=$($SHCTL $KEY control shpte ssolstat | grep "pid=$PID" | sed -n 's/.*ssol\[\([0-9]*\)\].*/\1/p' | head -1)
[ -z "$SLOT" ] && SLOT=0
echo "[g] ssol_add armed in slot=$SLOT"

echo "[g] guard mode -> $MODE"
$SHCTL $KEY control shpte "ssolguard $MODE"

if [ "$POISON" != "none" ]; then
  echo "[g] poison slot=$SLOT woff=0 val=$POISON"
  $SHCTL $KEY control shpte "ssolpoison $SLOT 0 $POISON"
fi

echo "[g] GO"
touch "$GO"
for i in $(seq 1 80); do
  grep -q '^DONE' "$OUT" && break
  grep -q 'TIMEOUT' "$OUT" && break
  sleep 0.1
done
sleep 0.3

echo "[g] ===== ssolstat ====="
$SHCTL $KEY control shpte ssolstat
echo "[g] ===== target out ====="
cat "$OUT"
wait "$TPID" 2>/dev/null; echo "[g] target_rc=$?"
echo "[g] ===== ssol_add result + crash check ====="
grep '^ssol_add' "$OUT" || echo "  (no ssol_add line -> target died before printing -> likely SIGILL)"
