#!/bin/bash

# Project ODA — Trace & Strike Cross-Platform Execution Wrapper
# Designed for Unix-like operating systems (Linux, macOS, WSL, etc.)

# Set working directory to script's directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

# Automatically find and terminate any previous ODA server on port 8765
echo "Ensuring port 8765 is free..."
PREV_PID=$(pgrep -f "com.oda.demo.DashboardServer")
if [ -n "$PREV_PID" ]; then
    echo "[CLEANUP] Automatically releasing port 8765 (Terminating PID: $PREV_PID)..."
    kill -9 $PREV_PID &>/dev/null
    sleep 0.5
fi

# Ensure Java is installed
if ! command -v java &> /dev/null; then
    echo "[ERROR] Java not found. Please install JDK 17+ and add it to your PATH."
    echo "To install Java, run:"
    echo "  Ubuntu/Debian: sudo apt update && sudo apt install openjdk-17-jdk"
    echo "  macOS:         brew install openjdk@17"
    echo "Or download from the official Oracle Java site:"
    echo "  https://www.oracle.com/java/technologies/downloads/"
    exit 1
fi

# Build project if JAR does not exist
JAR_PATH="target/project-oda-1.0.0.jar"
if [ ! -f "$JAR_PATH" ]; then
    echo "Built executable JAR not found. Compiling the project..."
    if command -v mvn &> /dev/null; then
        mvn package -q
    else
        echo "[ERROR] Maven ('mvn') is not installed and built JAR is missing."
        echo "Please install Maven to compile this project or build it in your IDE."
        exit 1
    fi

    if [ ! -f "$JAR_PATH" ]; then
        echo "[ERROR] Build failed. Maven did not produce '$JAR_PATH'."
        exit 1
    fi
    echo "JAR built successfully!"
fi

# Run the SAST + DAST pipeline
echo "=========================================================="
echo " Running TRACE (SAST) + STRIKE (DAST) Pipeline... "
echo "=========================================================="
java -jar "$JAR_PATH"
if [ $? -ne 0 ]; then
    echo "[ERROR] Security pipeline failed."
    exit 1
fi

echo ""
echo "Starting local ODA Dashboard Server..."
java -cp "$JAR_PATH" com.oda.demo.DashboardServer &
SERVER_PID=$!

# Graceful cleanup trap to terminate the server when the script exits or is interrupted
cleanup() {
    # Reset all traps to avoid recursion during exit
    trap - EXIT SIGINT SIGTERM TSTP
    
    echo ""
    echo "Stopping ODA Dashboard Server (PID: $SERVER_PID)..."
    kill $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
    
    # Clear the terminal screen and return a clean prompt
    clear
    exit 0
}
trap cleanup EXIT SIGINT SIGTERM TSTP

# Give the server a moment to bind the port
sleep 1.5

URL="http://localhost:8765/dashboard.html"
echo "Attempting to open the browser at $URL..."

if command -v xdg-open &> /dev/null; then
    xdg-open "$URL" &>/dev/null &
elif command -v open &> /dev/null; then
    open "$URL" &>/dev/null &
elif command -v explorer.exe &> /dev/null; then
    explorer.exe "$URL" &>/dev/null &
else
    echo "[INFO] No supported desktop open utility found."
fi

echo ""
echo "================================================================="
echo "  Trace & Strike Security Dashboard is live!"
echo "  URL: $URL"
echo "  "
echo "  Press [Ctrl+C] to stop the dashboard server and close."
echo "================================================================="
echo ""

# Keep running in foreground to preserve the background process
while true; do
    sleep 1
done
