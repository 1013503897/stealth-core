#!/system/bin/sh
# syscall-bridge test (device-side, root).
#   adb shell su -c 'sh /data/local/tmp/run_bridge_test.sh <APATCH_SUPERKEY>'
# A privileged controller (shctl + superkey) arms the bridge; bridgetool then
# drives the KPM with NO superkey via the magic personality() syscall. Proof: the
# "probe" command returns the resolved kernel symbol addresses to bridgetool, and
# a real personality() query still passes through.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_bridge_test.sh <superkey>"; exit 2; }

echo "== load shpte =="
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm

echo "== controller arms the bridge (with superkey) =="
timeout 10 $C control shpte bridge

echo "== bridgetool runs 'probe' WITHOUT a superkey (via magic syscall) =="
$TMP/bridgetool probe

echo "== bridgetool runs 'dump' without a superkey =="
$TMP/bridgetool dump

echo "== controller disarms the bridge =="
timeout 10 $C control shpte unbridge

echo "== bridgetool 'probe' again -> should now be empty (bridge off) =="
$TMP/bridgetool probe

echo "== unload =="
timeout 10 $C unload shpte
echo "== done =="
