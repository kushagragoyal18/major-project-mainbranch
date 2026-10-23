#!/usr/bin/env sh
# test:202 — one-command local start (macOS / Linux)
#   ./start.sh
set -e
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ] || ! .venv/bin/python -c "import flask, waitress" 2>/dev/null; then
  echo "Creating Python environment..."
  python3 -m venv .venv
  .venv/bin/python -m pip install --quiet --upgrade pip
  .venv/bin/python -m pip install --quiet -r requirements.txt
fi

if [ ! -f client/ui/dist/index.html ]; then
  echo "Building the web client..."
  (cd client/ui && npm install --silent && npm run build)
fi

export ABE_MODE="${ABE_MODE:-simulated}"
exec .venv/bin/python -m server.app
