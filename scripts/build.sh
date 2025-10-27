#!/bin/bash

set -e

VERSION=${VERSION:-"1.0.0"}
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}"

echo "╔═══════════════════════════════════════════════════════╗"
echo "║    Building Aegis Sentinel Suite - All Modules       ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "Version:    ${VERSION}"
echo "Commit:     ${COMMIT}"
echo "Build Date: ${BUILD_DATE}"
echo ""

mkdir -p bin

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Building Module 1: Aegis (Scanner & Reconnaissance)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
go build -ldflags="${LDFLAGS}" -o bin/aegis ./cmd/aegis
echo "✓ aegis built successfully"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Building Module 2: Gatehound (Passive Defense)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
go build -ldflags="${LDFLAGS}" -o bin/gatehound ./cmd/gatehound
echo "✓ gatehound built successfully"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Building Module 3: Revenant (Response Orchestrator)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
go build -ldflags="${LDFLAGS}" -o bin/revenant ./cmd/revenant
echo "✓ revenant built successfully"
echo ""

echo "╔═══════════════════════════════════════════════════════╗"
echo "║              Build Completed Successfully             ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "Binaries location:"
echo "  • bin/aegis      - Core scanner and reconnaissance"
echo "  • bin/gatehound  - Passive defense and monitoring"
echo "  • bin/revenant   - Response orchestration"
echo ""
echo "To install system-wide, run:"
echo "  sudo cp bin/aegis /usr/local/bin/"
echo "  sudo cp bin/gatehound /usr/local/bin/"
echo "  sudo cp bin/revenant /usr/local/bin/"
echo ""
