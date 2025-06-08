#!/bin/bash

# Exit on error
set -e

# Ensure dependencies are installed
echo "Checking dependencies..."
command -v python3 >/dev/null 2>&1 || { echo >&2 "Python3 required but not installed."; exit 1; }
command -v node >/dev/null 2>&1 || { echo >&2 "Node.js required but not installed."; exit 1; }

# Start the Python ping server in the background
echo "Starting py-libp2p server..."
cd ../py_node
python3 ping.py server --port 8000 > py_server.log 2>&1 &
PY_PID=$!
sleep 2  # Give the server time to start

# Get the peer ID from the server logs
PEER_ID=$(grep "Peer ID:" py_server.log | awk '{print $NF}')
if [ -z "$PEER_ID" ]; then
  echo "Error: Could not extract Peer ID from py-libp2p server logs"
  kill $PY_PID
  exit 1
fi
echo "Python server Peer ID: $PEER_ID"

# Start the JavaScript ping client
echo "Starting js-libp2p client..."
cd ../js_node
node ping.js client /ip4/127.0.0.1/tcp/8000/p2p/$PEER_ID 5 > js_client.log 2>&1 &
JS_PID=$!
sleep 10  # Allow pings to complete

# Check results
echo "Checking test results..."
if grep -q "Ping.*successful" js_client.log; then
  echo "✅ Test passed: Successful ping response detected"
else
  echo "❌ Test failed: No successful pings detected"
  echo "Python server logs:"
  cat ../py_node/py_server.log
  echo "JavaScript client logs:"
  cat js_client.log
fi

# Clean up
echo "Cleaning up..."
kill $PY_PID $JS_PID 2>/dev/null || true
exit 0