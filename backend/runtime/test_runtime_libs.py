"""Tests for the trusted-build ELF shared library collector."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('collect-runtime-libs.py')


class RuntimeLibraries(unittest.TestCase):
    def collector(self):
        self.assertTrue(SCRIPT.exists(), 'missing runtime library collector')
        spec = importlib.util.spec_from_file_location('runtime_libs', SCRIPT)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_parse_loader_library_and_vdso(self):
        collector = self.collector()
        self.assertEqual(collector.parse_ldd('linux-vdso.so.1 (0x1)\n libssl.so.3 => /lib/libssl.so.3 (0x2)\n /lib/ld-linux.so.2 (0x3)'),
                         [Path('/lib/libssl.so.3'), Path('/lib/ld-linux.so.2')])

    def test_missing_and_relative_library_fail(self):
        collector = self.collector()
        for value in ('libssl.so => not found', 'libssl.so => relative/path (0x1)'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                collector.parse_ldd(value)

    def test_symlinks_preserved_and_conflicts_rejected(self):
        collector = self.collector()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'lib.so.1'
            source.write_bytes(b'native')
            alias = root / 'lib.so'
            alias.symlink_to(source.name)
            out = root / 'out'
            collector.copy_library(alias, out)
            dest = out / alias.relative_to('/')
            self.assertTrue(dest.is_symlink())
            self.assertEqual(dest.read_bytes(), b'native')
            (out / source.relative_to('/')).write_bytes(b'collision')
            with self.assertRaises(ValueError):
                collector.copy_library(source, out)


if __name__ == '__main__':
    unittest.main()
