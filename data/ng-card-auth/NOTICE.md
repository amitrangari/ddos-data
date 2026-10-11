# NOTICE

This directory contains a copy of a third-party dataset, redistributed under the terms of
the Apache License, Version 2.0 (full text in `LICENSE`). Its records are unmodified; only
the file was split into four parts (see "Modifications").

- **Dataset:** Nigerian Banking Card Transactions
- **Creator:** electricsheepafrica
- **Source:** https://huggingface.co/datasets/electricsheepafrica/nigerian-banking-card-transactions
- **License:** Apache-2.0 (confirmed on the dataset's Hugging Face page at time of download)
- **Files:** `parts/part-000.parquet` … `parts/part-003.parquet` (3,000,000 rows total,
  18 columns). Source file: the auto-converted parquet mirror
  `nigerian-banking-card-transactions.parquet`, 185,865,827 bytes, SHA-256
  `4dcff89acdecb6784c8024a44c3bd15bb8fd76a0ed574e3197c2487b40bee09c`.
- **Downloaded:** 2026-06-17
- **Modifications (2026-10-10, per Apache-2.0 §4(b)):** the single source parquet file was
  split by contiguous row ranges into four Snappy-compressed parts of 750,000 rows each, so
  each part stays under GitHub's 100 MB per-file limit and the Zenodo archive contains the
  data itself (v1.0.0 archived only a Git LFS pointer). No row, column, value, or row order
  was changed: `pyarrow.parquet.read_table("parts")` is `Table.equals()` to the source file.
  Load with `pd.read_parquet("data/ng-card-auth/parts")`.

## Why this dataset is bundled here

This dataset is cited in the TIG-CDO manuscript (electricsheepafrica 2026) and is the
empirical source for the FDCE / R-11 decline-code
calibration reported in Section VI.I (organic decline-code p99 = 0.712, false-positive rate
0.023%, Cohen's *d* = 7.67 versus the simulated FDCE attack). The Apache-2.0 license permits
redistribution, so — unlike the APA-DDoS dataset in this same package, whose license is
unconfirmed — this dataset is included here as data, not just as a pointer, so the FDCE
calibration in `calibrate_fdce_from_real_data.py` is fully reproducible offline.

## Attribution

Per Apache-2.0 §4, this NOTICE file and the accompanying `LICENSE` file must be preserved in
any redistribution of this dataset or derivative works of it.
