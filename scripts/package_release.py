"""Упаковка проверенного release-бинарника и публичной документации."""

import argparse
import gzip
import hashlib
import io
import json
import logging
import os
import re
import subprocess
import tarfile
import urllib.request
import zipfile
from pathlib import Path

import tomllib

PUBLIC_FILES = (
    "config.example.toml",
    "README.md",
    "LICENSE-AGPL.txt",
    "LICENSE-TON-VANITY.txt",
    "THIRD-PARTY-NOTICES.md",
)
PLATFORMS = ("linux-x86_64", "windows-x86_64")
MAX_LICENSE_SIZE = 1024 * 1024
LOGGER = logging.getLogger(__name__)


def read_public(path: Path) -> bytes:
    """Не допускаем подмену явно разрешённого файла символической ссылкой."""
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Ожидался обычный публичный файл: {path}")
    return path.read_bytes()


def download_license(entry: dict[str, str], cache: dict[str, bytes]) -> bytes:
    url = entry["url"]
    if not re.fullmatch(
        r"https://raw\.githubusercontent\.com/[\w.-]+/[\w.-]+/[0-9a-f]{40}/[\w./-]+",
        url,
    ):
        raise ValueError(f"Недопустимый закреплённый источник лицензии: {url}")
    if url not in cache:
        with urllib.request.urlopen(url, timeout=30) as response:
            if hasattr(response, "geturl") and response.geturl() != url:
                raise ValueError(f"Перенаправление источника лицензии: {url}")
            data = response.read(MAX_LICENSE_SIZE + 1)
        if len(data) > MAX_LICENSE_SIZE:
            raise ValueError(f"Лицензия превышает лимит размера: {url}")
        cache[url] = data
    data = cache[url]
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError(f"Не совпадает SHA256 лицензии: {url}")
    return data


def dependency_licenses(root: Path, metadata: dict) -> dict[str, bytes]:
    fallback_path = root / "scripts/license-sources.json"
    fallbacks = (
        json.loads(fallback_path.read_text(encoding="utf-8"))
        if fallback_path.exists()
        else {}
    )
    result: dict[str, bytes] = {}
    cache: dict[str, bytes] = {}
    index = [
        "# Лицензии зависимостей",
        "",
        "Включены все пакеты Cargo metadata, включая dev-зависимости.",
        "",
    ]
    for package in sorted(
        metadata["packages"], key=lambda p: (p["name"], p["version"])
    ):
        if package["id"] == metadata.get("resolve", {}).get("root"):
            continue
        name = f"{package['name']}-{package['version']}"
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", name):
            raise ValueError(f"Недопустимое имя зависимости: {name}")
        source = Path(package["manifest_path"]).parent
        files = {
            path
            for path in source.iterdir()
            if path.is_file()
            and path.name.upper().startswith(("LICENSE", "COPYING", "NOTICE"))
        }
        # У r-efi полный текст MIT и copyright включены в AUTHORS.
        if name == "r-efi-6.0.0":
            files.add(source / "AUTHORS")
        license_file = package.get("license_file")
        if license_file:
            path = source / license_file
            if not path.resolve().is_relative_to(source.resolve()):
                raise ValueError(f"Лицензия вне каталога зависимости: {name}")
            files.add(path)
        if files:
            for path in sorted(files):
                relative = path.relative_to(source).as_posix()
                result[f"dependency-licenses/{name}/{relative}"] = read_public(path)
        else:
            entries = fallbacks.get(name)
            if not entries:
                raise ValueError(f"Не найден текст лицензии: {name}")
            for entry in entries:
                filename = entry["filename"]
                if Path(filename).name != filename or filename in (".", ".."):
                    raise ValueError(f"Недопустимое имя файла лицензии: {name}")
                result[f"dependency-licenses/{name}/{filename}"] = download_license(
                    entry, cache
                )
        index.append(f"- {name}: `{package.get('license') or 'см. текст лицензии'}`")
    result["dependency-licenses/INDEX.md"] = ("\n".join(index) + "\n").encode()
    return result


def package_release(root: Path, platform: str, output: Path, metadata: dict) -> Path:
    if platform not in PLATFORMS:
        raise ValueError(f"Неизвестная платформа: {platform}")
    version = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))[
        "package"
    ]["version"]
    if not re.fullmatch(r"[0-9A-Za-z.+-]+", version):
        raise ValueError("Недопустимая версия пакета")
    binary = "brut-wallet.exe" if platform.startswith("windows") else "brut-wallet"
    target = Path(os.environ.get("CARGO_TARGET_DIR", str(root / "target")))
    if not target.is_absolute():
        target = root / target
    files = {name: read_public(root / name) for name in PUBLIC_FILES}
    docs = root / "docs"
    if docs.is_symlink():
        raise ValueError("Каталог docs не должен быть символической ссылкой")
    files.update({f"docs/{p.name}": read_public(p) for p in sorted(docs.glob("*.md"))})
    files[binary] = read_public(target / "release" / binary)
    files.update(dependency_licenses(root, metadata))
    output.mkdir(parents=True, exist_ok=True)
    suffix = ".zip" if platform.startswith("windows") else ".tar.gz"
    archive = output / f"ton-vanity-rs-v{version}-{platform}{suffix}"
    if suffix == ".zip":
        with zipfile.ZipFile(
            archive, "w", compression=zipfile.ZIP_DEFLATED, strict_timestamps=False
        ) as stream:
            for name, data in sorted(files.items()):
                info = zipfile.ZipInfo(
                    f"ton-vanity-rs/{name}", date_time=(1980, 1, 1, 0, 0, 0)
                )
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                stream.writestr(info, data)
    else:
        with (
            archive.open("wb") as raw,
            gzip.GzipFile(fileobj=raw, filename="", mode="wb", mtime=0) as compressed,
            tarfile.open(fileobj=compressed, mode="w") as stream,
        ):
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(f"ton-vanity-rs/{name}")
                info.size = len(data)
                info.mode = 0o755 if name == binary else 0o644
                stream.addfile(info, io.BytesIO(data))
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    Path(f"{archive}.sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="utf-8"
    )
    return archive


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=PLATFORMS)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        metadata = json.loads(
            subprocess.check_output(
                ["cargo", "metadata", "--locked", "--format-version", "1"],
                cwd=root,
                text=True,
            )
        )
        archive = package_release(root, args.platform, args.output, metadata)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        LOGGER.error("Упаковка прервана: %s", error)
        return 1
    LOGGER.info("Созданы %s и %s.sha256", archive, archive)
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    raise SystemExit(main())
