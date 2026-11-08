"""Проверки содержимого и воспроизводимости release-архивов."""

import hashlib
import os
import tarfile
import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import package_release as release


class PackageReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "dist"
        environment = patch.dict(
            os.environ, {"CARGO_TARGET_DIR": str(self.root / "target")}
        )
        environment.start()
        self.addCleanup(environment.stop)
        for name in release.PUBLIC_FILES:
            self.write(name, f"Публичный {name}".encode())
        self.write("Cargo.toml", b'[package]\nversion = "1.0.0"\n')
        self.write("docs/guide.md", b"guide")
        for name in ("session.toml", "wallets.txt", "master-key.bin", "artifacts/x.md"):
            self.write(name, b"SECRET")
        self.write("target/release/brut-wallet", b"linux binary")
        self.write("target/release/brut-wallet.exe", b"windows binary")
        self.crate = self.root / "crate"
        self.write("crate/LICENSE-MIT", b"license text")
        self.crate_metadata = {
            "id": "example",
            "name": "example",
            "version": "1.2.3",
            "manifest_path": str(self.crate / "Cargo.toml"),
            "license": "MIT",
            "license_file": None,
        }
        self.metadata = {"packages": [self.crate_metadata], "resolve": {"root": "root"}}

    def write(self, name: str, data: bytes) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def package(self, platform: str) -> Path:
        return release.package_release(self.root, platform, self.output, self.metadata)

    def test_linux_allowlist_mode_checksum_and_reproducibility(self) -> None:
        archive = self.package("linux-x86_64")
        expected = {f"ton-vanity-rs/{name}" for name in release.PUBLIC_FILES}
        expected |= {
            "ton-vanity-rs/brut-wallet",
            "ton-vanity-rs/docs/guide.md",
            "ton-vanity-rs/dependency-licenses/example-1.2.3/LICENSE-MIT",
            "ton-vanity-rs/dependency-licenses/INDEX.md",
        }
        with tarfile.open(archive) as stream:
            self.assertEqual(set(stream.getnames()), expected)
            self.assertEqual(stream.getmember("ton-vanity-rs/brut-wallet").mode, 0o755)
            for item in stream:
                self.assertNotIn(b"SECRET", stream.extractfile(item).read())
        before = archive.read_bytes()
        self.assertEqual(self.package("linux-x86_64").read_bytes(), before)
        self.assertEqual(
            Path(f"{archive}.sha256").read_text(),
            f"{hashlib.sha256(before).hexdigest()}  {archive.name}\n",
        )

    def test_windows_accepts_old_timestamps(self) -> None:
        os.utime(self.root / "README.md", (1, 1))
        archive = self.package("windows-x86_64")
        with zipfile.ZipFile(archive) as stream:
            self.assertEqual(
                stream.read("ton-vanity-rs/brut-wallet.exe"), b"windows binary"
            )
            self.assertEqual(
                stream.getinfo("ton-vanity-rs/README.md").date_time[0], 1980
            )
            self.assertNotIn("ton-vanity-rs/session.toml", stream.namelist())
        before = archive.read_bytes()
        self.assertEqual(self.package("windows-x86_64").read_bytes(), before)

    def test_missing_license_fails_before_creating_archive(self) -> None:
        (self.crate / "LICENSE-MIT").unlink()
        with self.assertRaisesRegex(ValueError, "example-1.2.3"):
            self.package("linux-x86_64")
        self.assertFalse(self.output.exists())

    def test_license_file_and_notice_are_included(self) -> None:
        self.write("crate/legal/terms.txt", b"custom license")
        self.write("crate/NOTICE", b"notice")
        self.crate_metadata["license_file"] = "legal/terms.txt"
        with tarfile.open(self.package("linux-x86_64")) as stream:
            self.assertIn(
                "ton-vanity-rs/dependency-licenses/example-1.2.3/legal/terms.txt",
                stream.getnames(),
            )
            self.assertIn(
                "ton-vanity-rs/dependency-licenses/example-1.2.3/NOTICE",
                stream.getnames(),
            )

    def test_r_efi_license_is_embedded_in_authors(self) -> None:
        (self.crate / "LICENSE-MIT").unlink()
        self.crate_metadata.update(name="r-efi", version="6.0.0")
        self.write("crate/AUTHORS", b"LICENSE: MIT license and copyright")
        with tarfile.open(self.package("linux-x86_64")) as stream:
            self.assertEqual(
                stream.extractfile(
                    "ton-vanity-rs/dependency-licenses/r-efi-6.0.0/AUTHORS"
                ).read(),
                b"LICENSE: MIT license and copyright",
            )

    def test_symlink_public_file_is_rejected(self) -> None:
        (self.root / "README.md").unlink()
        try:
            (self.root / "README.md").symlink_to(self.root / "wallets.txt")
        except OSError as error:
            if getattr(error, "winerror", None) == 1314:
                self.skipTest("Windows не разрешает создание символических ссылок")
            raise
        with self.assertRaises(ValueError):
            self.package("linux-x86_64")

    def test_fallback_download_checks_hash_and_caches(self) -> None:
        # Сетевой транспорт заменён, проверка checksum остаётся настоящей.
        data = b"pinned license"
        entry = {
            "url": "https://raw.githubusercontent.com/a/b/" + "a" * 40 + "/LICENSE",
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        with patch("urllib.request.urlopen", return_value=BytesIO(data)) as request:
            cache: dict[str, bytes] = {}
            self.assertEqual(release.download_license(entry, cache), data)
            self.assertEqual(release.download_license(entry, cache), data)
            self.assertEqual(request.call_count, 1)
            with self.assertRaises(ValueError):
                release.download_license({**entry, "sha256": "0" * 64}, cache)


if __name__ == "__main__":
    unittest.main()
