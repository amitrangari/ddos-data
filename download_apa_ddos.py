#!/usr/bin/env python3
"""
Retrieval script for the APA-DDoS dataset.

This dataset's license is listed as "unknown" on both its original Kaggle page
and its Hugging Face mirror, so it is NOT bundled as a data file in this
package (see README.md for why). This script fetches it directly from its
original public sources instead, so you get it under whatever terms the host
platform and creator actually offer -- not a redistributed copy from us.

Writes: ../data/apa-ddos/apa-ddos.parquet
        (~3.6 MB, 151,200 rows, 23 columns)

Tries two routes in order:
  1. Hugging Face mirror (A7K/APA-DDoS) via the `datasets` library -- no
     account or API key needed, this is a public dataset.
  2. Kaggle, via the `kaggle` CLI/API -- needs a Kaggle account and an API
     token (~/.kaggle/kaggle.json). Original source: dataset owner
     yashwanthkumbam, slug `apaddos-dataset`.

If BOTH of these fail (network restrictions, a package not installed, the
mirror or listing having moved, etc.), see "If the download script fails" in
README.md for exact manual-download steps -- this is a normal, expected
fallback path, not a sign that something is broken.

Requires: `datasets` and/or `kaggle` (pip install datasets  /  pip install kaggle)
          pandas, pyarrow (for the parquet write)
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT_DIR = HERE / "data" / "apa-ddos"
OUT_FILE = OUT_DIR / "apa-ddos.parquet"

HF_REPO = "A7K/APA-DDoS"
KAGGLE_DATASET = "yashwanthkumbam/apaddos-dataset"
KAGGLE_URL = f"https://www.kaggle.com/datasets/{KAGGLE_DATASET}"
HF_URL = f"https://huggingface.co/datasets/{HF_REPO}"


def try_huggingface() -> bool:
    print(f"[1/2] Trying Hugging Face mirror: {HF_URL}")
    try:
        from datasets import load_dataset
    except ImportError:
        print("      'datasets' package not installed (pip install datasets). Skipping.")
        return False
    try:
        ds = load_dataset(HF_REPO, split="train")
        df = ds.to_pandas()
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        df.to_parquet(OUT_FILE, index=False)
        print(f"      OK: wrote {len(df):,} rows -> {OUT_FILE}")
        return True
    except Exception as e:
        print(f"      Failed: {e}")
        return False


def try_kaggle() -> bool:
    print(f"[2/2] Trying Kaggle: {KAGGLE_URL}")
    try:
        import kaggle  # noqa: F401
    except ImportError:
        print("      'kaggle' package not installed, or ~/.kaggle/kaggle.json missing.")
        print("      pip install kaggle   (then set up an API token: "
              "https://www.kaggle.com/docs/api#authentication)")
        return False
    try:
        import subprocess
        import zipfile
        import pandas as pd

        OUT_DIR.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["kaggle", "datasets", "download", "-d", KAGGLE_DATASET, "-p", str(OUT_DIR)],
            check=True,
        )
        zip_path = OUT_DIR / "apaddos-dataset.zip"
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(OUT_DIR)
        csv_candidates = list(OUT_DIR.rglob("*.csv"))
        if not csv_candidates:
            print("      Downloaded, but no CSV found after extraction -- inspect "
                  f"{OUT_DIR} manually.")
            return False
        df = pd.read_csv(csv_candidates[0])
        df.to_parquet(OUT_FILE, index=False)
        print(f"      OK: wrote {len(df):,} rows -> {OUT_FILE}")
        return True
    except Exception as e:
        print(f"      Failed: {e}")
        return False


def main():
    if OUT_FILE.exists():
        print(f"Already present: {OUT_FILE} -- delete it first if you want to re-fetch.")
        return 0

    if try_huggingface():
        return 0
    if try_kaggle():
        return 0

    print()
    print("=" * 72)
    print("Both automatic download routes failed. This is expected if you're")
    print("offline, don't have a Kaggle API token set up, or the package versions")
    print("differ. Manual download instructions are in README.md under")
    print("'If the download script fails' -- follow those steps, then place the")
    print(f"resulting file at:\n  {OUT_FILE}")
    print("=" * 72)
    return 1


if __name__ == "__main__":
    sys.exit(main())
