#!/bin/bash
# Crea la estructura de carpetas de Jagi-Sentinel
mkdir -p modules static/css static/js static/img templates database reports logs tests
touch modules/__init__.py
touch modules/network_manager.py
touch modules/device_discovery.py
touch modules/normalizer.py
touch modules/vulnerability_lookup.py
touch modules/risk_engine.py
touch modules/report_generator.py
touch static/css/style.css
touch static/js/dashboard.js
touch templates/index.html
touch templates/analysis.html
touch templates/dashboard.html
touch templates/history.html
touch tests/test_network_manager.py
touch tests/test_normalizer.py
touch tests/test_risk_engine.py
touch app.py
touch README.md
echo "Estructura creada correctamente:"
find . -maxdepth 2 -not -path '*/.*'