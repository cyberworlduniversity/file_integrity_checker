import json
import tempfile
import unittest
from pathlib import Path

from file_integrity_checker import save_database


class AtomicDatabaseWriteTests(unittest.TestCase):
    def test_writes_valid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            save_database({"file.txt": {"hash": "abc", "algorithm": "sha256"}}, str(path))
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["file.txt"]["hash"], "abc")

    def test_failed_serialization_preserves_existing_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            path.write_text("previous baseline", encoding="utf-8")
            with self.assertRaises(TypeError):
                save_database({"invalid": object()}, str(path))
            self.assertEqual(path.read_text(encoding="utf-8"), "previous baseline")

    def test_replaces_symlink_without_overwriting_its_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root / "protected.txt"
            protected.write_text("keep this", encoding="utf-8")
            database = root / "baseline.json"
            database.symlink_to(protected)

            save_database({"safe": {"hash": "123"}}, str(database))

            self.assertFalse(database.is_symlink())
            self.assertEqual(protected.read_text(encoding="utf-8"), "keep this")
            self.assertEqual(json.loads(database.read_text(encoding="utf-8"))["safe"]["hash"], "123")


if __name__ == "__main__":
    unittest.main()
