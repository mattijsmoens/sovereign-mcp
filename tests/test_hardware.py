"""Test hardware memory protection via ctypes fallback on Windows."""
import sys
import os
import hashlib
import unittest

# Add package to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sovereign_mcp.frozen_memory_fallback import freeze, verify, is_protected, destroy, page_size


class TestHardwareProtection(unittest.TestCase):
    """Hardware memory protection tests using ctypes fallback."""

    def test_page_size(self):
        """Verify page_size returns a reasonable value."""
        ps = page_size()
        self.assertGreater(ps, 0, "Page size should be positive")
        print(f"Page size: {ps}")

    def test_freeze_data(self):
        """Test 1: Freeze data."""
        data = b"FROZEN TOOL DEFINITION: get_weather sha256:abc123"
        buf = freeze(data)
        self.assertEqual(buf.size, len(data))
        self.assertTrue(buf.protected)
        destroy(buf)

    def test_read_back_data(self):
        """Test 2: Read back frozen data matches original."""
        data = b"FROZEN TOOL DEFINITION: get_weather sha256:abc123"
        buf = freeze(data)
        readback = buf.data
        self.assertEqual(readback, data, "Data mismatch on readback")
        destroy(buf)

    def test_verify_hash(self):
        """Test 3: SHA-256 hash verification."""
        data = b"FROZEN TOOL DEFINITION: get_weather sha256:abc123"
        buf = freeze(data)
        expected_hash = hashlib.sha256(data).digest()
        self.assertTrue(verify(buf, expected_hash), "Hash verification failed")
        destroy(buf)

    def test_protection_status(self):
        """Test 4: Memory is read-only protected."""
        data = b"FROZEN TOOL DEFINITION: get_weather sha256:abc123"
        buf = freeze(data)
        self.assertTrue(is_protected(buf), "Memory should be protected")
        destroy(buf)

    def test_wrong_hash_rejected(self):
        """Test 5: Wrong hash correctly rejected."""
        data = b"FROZEN TOOL DEFINITION: get_weather sha256:abc123"
        buf = freeze(data)
        wrong_hash = hashlib.sha256(b"wrong data").digest()
        self.assertFalse(verify(buf, wrong_hash), "Wrong hash should fail")
        destroy(buf)

    def test_destroy_and_second_buffer(self):
        """Test 6-7: Destroy and second buffer lifecycle."""
        data = b"FROZEN TOOL DEFINITION: get_weather sha256:abc123"
        buf = freeze(data)
        destroy(buf)

        data2 = b"SECOND BUFFER TEST"
        buf2 = freeze(data2)
        self.assertTrue(is_protected(buf2), "Second buffer should be protected")
        readback2 = buf2.data
        self.assertEqual(readback2, data2)
        destroy(buf2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
