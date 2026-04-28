#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec gunicorn --workers 1 --threads 2 --bind 0.0.0.0:8000 wsgi:app
