import contextlib
import io
import tempfile
import unittest
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from browser_cache_ioc_scanner import discover_caches, discover_home_caches, main, markers, scan_file


class ScannerTests(unittest.TestCase):
    def test_cache_discovery_and_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / 'brave' / 'Default' / 'Cache' / 'Cache_Data'
            cache.mkdir(parents=True)
            (cache / 'cache_1').write_bytes(b'track.js loads 1688360.cc from a test fixture')
            self.assertEqual(discover_caches(root, 12), {cache})
            self.assertIn('IOC:1688360.cc', scan_file(cache / 'cache_1', markers([])))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(['--root', str(root)])
            self.assertEqual(code, 0)
            self.assertIn('hit_files=1', output.getvalue())
            self.assertNotIn(tmp, output.getvalue())

    def test_overlap_across_chunk_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'binary'
            path.write_bytes(b'X' * (1024 * 1024 - 4) + b'1688360.cc')
            self.assertIn('IOC:1688360.cc', scan_file(path, markers([])))

    def test_automatic_home_discovery_nested_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            cache = home / 'custom' / 'isolated' / 'profile' / 'Default' / 'Cache' / 'Cache_Data'
            cache.mkdir(parents=True)
            (cache / 'hit').write_bytes(b'Example contains 1688360.cc in an isolated cache')
            found, incomplete = discover_home_caches(home, 12)
            self.assertFalse(incomplete)
            self.assertIn(cache, found)
            with patch('pathlib.Path.home', return_value=home):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = main([])
            self.assertEqual(code, 0)
            self.assertIn('hit_files=1', output.getvalue())
            self.assertNotIn(tmp, output.getvalue())

    def test_home_discovery_skips_document_folders(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            skipped = home / 'Documents' / 'profile' / 'Default' / 'Cache' / 'Cache_Data'
            skipped.mkdir(parents=True)
            found, incomplete = discover_home_caches(home, 12)
            self.assertFalse(incomplete)
            self.assertNotIn(skipped, found)
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(['--root', str(home / 'Documents')])
            self.assertEqual(code, 0)

    def test_budget_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'home'
            elsewhere = Path(tmp) / 'elsewhere'
            cache = elsewhere / 'Default' / 'Cache' / 'Cache_Data'
            cache.mkdir(parents=True)
            home.mkdir()
            (home / 'linked-profile').symlink_to(elsewhere, target_is_directory=True)
            found, incomplete = discover_home_caches(home, 12)
            self.assertFalse(incomplete)
            self.assertEqual(found, set())
            (home / 'a').mkdir()
            (home / 'b').mkdir()
            _, incomplete = discover_home_caches(home, 12, max_directories=1)
            self.assertTrue(incomplete)

    def test_no_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(['--root', tmp])
            self.assertEqual(code, 2)


if __name__ == '__main__':
    unittest.main()
