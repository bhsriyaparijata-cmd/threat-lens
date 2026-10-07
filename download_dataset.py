"""
download_dataset.py
---------------------
Downloads and extracts the SpamAssassin Public Corpus, which is the ONLY
dataset used to train the ML email-content classifier in this project.

Usage:
    python download_dataset.py

Output layout:
    data/raw/spam/*      -> raw spam messages
    data/raw/ham/*       -> raw legitimate ("ham") messages

Note: this script needs outbound internet access to
spamassassin.apache.org. If your environment has no internet access,
download the archives manually from:
    https://spamassassin.apache.org/old/publiccorpus/
and extract them into data/raw/spam and data/raw/ham following the same
layout before running train_model.py.
"""

import os
import tarfile
import urllib.request
from pathlib import Path

BASE_URL = "https://spamassassin.apache.org/old/publiccorpus/"

# A small, well-known subset of the public corpus. Feel free to add more
# archives from the same index for a larger training set.
ARCHIVES = {
    "spam": [
        "20050311_spam_2.tar.bz2",
    ],
    "ham": [
        "20030228_easy_ham.tar.bz2",
    ],
}

RAW_DIR = Path(__file__).parent / "data" / "raw"


def _download(url: str, dest: Path) -> None:
    if dest.exists():
        print(f"[skip] {dest.name} already downloaded")
        return
    print(f"[download] {url}")
    urllib.request.urlretrieve(url, dest)


def _extract(archive_path: Path, target_dir: Path) -> None:
    print(f"[extract] {archive_path.name} -> {target_dir}")
    with tarfile.open(archive_path, "r:bz2") as tar:
        tar.extractall(path=target_dir)


def main() -> None:
    for label, filenames in ARCHIVES.items():
        target_dir = RAW_DIR / label
        target_dir.mkdir(parents=True, exist_ok=True)

        for filename in filenames:
            archive_path = RAW_DIR / filename
            try:
                _download(BASE_URL + filename, archive_path)
                _extract(archive_path, target_dir)
            except Exception as exc:
                print(
                    f"[error] Could not fetch/extract {filename}: {exc}\n"
                    "         Download it manually from "
                    "https://spamassassin.apache.org/old/publiccorpus/ "
                    f"and place it in {RAW_DIR}"
                )

    print("\nDone. Verify data/raw/spam and data/raw/ham contain message files,")
    print("then run: python train_model.py")


if __name__ == "__main__":
    main()
