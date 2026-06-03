#!/system/bin/sh
# TracerPid spoof test (device-side, root).
#   adb shell su -c 'sh /data/local/tmp/run_tracer_test.sh <APATCH_SUPERKEY>'
# tracertest PTRACE_ATTACHes a child and reads its /proc/<child>/status TracerPid.
# Without spoof it shows the tracer's pid; with `hidetracer` it must show 0.
KEY="$1"
TMP=/data/local/tmp
C="$TMP/shctl $KEY"
[ -z "$KEY" ] && { echo "usage: run_tracer_test.sh <superkey>"; exit 2; }

echo "== load shpte =="
timeout 10 $C unload shpte 2>/dev/null
timeout 10 $C load $TMP/shpte.kpm

echo "== before spoof (TracerPid == tracer pid) =="
$TMP/tracertest

echo "== arm hidetracer =="
timeout 10 $C control shpte hidetracer

echo "== after spoof (TracerPid must be 0) =="
$TMP/tracertest

echo "== dump (tracer fields) =="
timeout 10 $C control shpte dump

echo "== unhidetracer =="
timeout 10 $C control shpte unhidetracer

echo "== after unhide (back to tracer pid) =="
$TMP/tracertest

echo "== unload =="
timeout 10 $C unload shpte
echo "== done =="
