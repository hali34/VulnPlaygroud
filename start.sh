#!/bin/bash
# VulnBank — Local Setup Script

set -e

echo "================================================="
echo "  VulnBank — OWASP Top 10 Demo App Setup"
echo "================================================="
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Please install Python 3.8+"
    exit 1
fi
echo "✅ Python3 found: $(python3 --version)"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate
source venv/bin/activate 2>/dev/null || . venv/Scripts/activate 2>/dev/null

# Install dependencies
echo "📥 Installing dependencies..."
pip install --quiet flask requests

echo ""
echo "================================================="
echo "  ⚠️  WARNING: This app is intentionally vulnerable"
echo "  ✅  Safe to run on localhost ONLY"
echo "  🔑  Credentials: admin/admin123  alice/password"
echo "================================================="
echo ""
echo "🚀 Starting VulnBank at http://127.0.0.1:5000"
echo ""

python app.py
