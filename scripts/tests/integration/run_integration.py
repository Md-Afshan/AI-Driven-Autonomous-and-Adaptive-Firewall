#!/usr/bin/env python3
"""
Shim that delegates to the repository's canonical integration test.

Run either:
  python tests/integration/run_integration.py
or
  ./scripts/tests/integration/run_integration.py

This file finds the canonical `tests/integration/run_integration.py` and execs it
using the current Python interpreter so the test runs in a consistent manner
regardless of the working directory.
"""
import os
import sys

HERE = os.path.abspath(os.path.dirname(__file__))
canonical = os.path.abspath(os.path.join(HERE, '..', '..', 'tests', 'integration', 'run_integration.py'))
if not os.path.exists(canonical):
    print(f"Could not find canonical integration test at {canonical}")
    sys.exit(2)

# Execute the canonical test file with the current Python interpreter
os.execv(sys.executable, [sys.executable, canonical] + sys.argv[1:])
