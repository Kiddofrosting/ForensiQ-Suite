#!/usr/bin/env python3
"""Test encryption functionality"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.utils import test_encryption

if __name__ == '__main__':
    print("=" * 60)
    print("  ForensIQ Suite - Encryption Test")
    print("=" * 60)

    if test_encryption():
        print("\n✅ All encryption tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Encryption tests failed!")
        sys.exit(1)