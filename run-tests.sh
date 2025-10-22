#!/bin/bash
# Wrapper script to run tests with proper library paths
# This is needed on macOS where libaes_siv might be installed in /usr/local/lib

set -e

# Ensure we're in the right directory
cd "$(dirname "$0")"

# Build if necessary
if [ ! -f .libs/test_runner ]; then
    echo "Building tests..."
    make test_runner
fi

# Set library path for macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    export DYLD_LIBRARY_PATH="/usr/local/lib:${DYLD_LIBRARY_PATH}"
fi

# Run the test runner directly
echo "Running tests..."
./.libs/test_runner
exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo ""
    echo "Test run completed successfully!"
else
    echo ""
    echo "Test run failed with exit code $exit_code"
fi

exit $exit_code
