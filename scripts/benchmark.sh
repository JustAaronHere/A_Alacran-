#!/bin/bash

set -e

echo "==================================="
echo "Aegis Performance Benchmark"
echo "==================================="
echo ""

if [ ! -f "bin/aegis" ]; then
    echo "Error: aegis binary not found. Run ./scripts/build.sh first"
    exit 1
fi

echo "Creating test target list..."
cat > /tmp/aegis-bench-targets.txt <<EOF
127.0.0.1
localhost
EOF

echo ""
echo "Benchmark 1: Quick scan (20 ports, localhost)"
time ./bin/aegis scan 127.0.0.1 --mode=quick --ports=1-20 --no-vuln --output=json > /dev/null

echo ""
echo "Benchmark 2: Discovery scan (small network)"
time ./bin/aegis discover 127.0.0.0/30 --method=tcp-syn > /dev/null

echo ""
echo "Benchmark 3: Comprehensive scan with fingerprinting"
time ./bin/aegis scan 127.0.0.1 --mode=comprehensive --ports=top100 --output=json > /dev/null

echo ""
echo "==================================="
echo "Benchmark completed!"
echo "==================================="

rm -f /tmp/aegis-bench-targets.txt
