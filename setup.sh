#!/bin/bash
# Quick Setup and Test Guide
# This script helps set up and test the vulnerability scanner

set -e

echo "======================================"
echo "Web Vulnerability Scanner - Setup"
echo "======================================"
echo ""

# Check Python version
echo "[*] Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "    Python version: $python_version"
echo ""

# Install dependencies
echo "[*] Installing dependencies..."
pip install -r requirements.txt > /dev/null 2>&1 || pip install -r requirements.txt
echo "    ✓ Dependencies installed"
echo ""

# Verify installation
echo "[*] Verifying installation..."
python3 -c "import requests; import bs4; import jinja2" 2>/dev/null && echo "    ✓ All modules importable" || echo "    ✗ Import failed"
echo ""

# Show usage
echo "[*] Scanner installed successfully!"
echo ""
echo "Quick Start Examples:"
echo "===================="
echo ""
echo "1. Basic scan:"
echo "   python -m scanner.main http://localhost:8080"
echo ""
echo "2. Scan with custom output:"
echo "   python -m scanner.main http://localhost:8080 -o ./my_reports"
echo ""
echo "3. Scan with verbose logging:"
echo "   python -m scanner.main http://localhost:8080 -v"
echo ""
echo "4. Deep crawl with longer timeout:"
echo "   python -m scanner.main http://localhost:8080 -d 3 -t 15"
echo ""
echo "5. Against DVWA (requires Docker):"
echo "   docker run --rm -it -p 80:80 vulnerables/web-dvwa"
echo "   # In another terminal:"
echo "   python -m scanner.main http://localhost -o ./dvwa_results -v"
echo ""
echo "6. Against Juice Shop (requires Docker):"
echo "   docker run --rm -it -p 3000:3000 bkimminich/juice-shop"
echo "   # In another terminal:"
echo "   python -m scanner.main http://localhost:3000 -o ./juice_results"
echo ""
echo "Get help:"
echo "==========="
echo "   python -m scanner.main --help"
echo ""
echo "Reports will be saved in: ./reports/ (or custom -o directory)"
echo "  - HTML: vulnerability_report_<timestamp>.html"
echo "  - JSON: vulnerability_report_<timestamp>.json"
echo ""
