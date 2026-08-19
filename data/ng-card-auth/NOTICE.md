# NOTICE

This directory contains an unmodified copy of a third-party dataset, redistributed
under the terms of the Apache License, Version 2.0 (full text in `LICENSE`).

- **Dataset:** Nigerian Banking Card Transactions
- **Creator:** electricsheepafrica
- **Source:** https://huggingface.co/datasets/electricsheepafrica/nigerian-banking-card-transactions
- **License:** Apache-2.0 (confirmed on the dataset's Hugging Face page at time of download)
- **File:** `nigerian-banking-card-transactions.parquet` (3,000,000 rows, 18 columns, ~177 MB
  uncompressed on the source page; auto-converted parquet mirror, 185,865,827 bytes as stored here)
- **Downloaded:** 2026-06-17
- **Modifications:** none — this is the dataset exactly as published by the creator.

## Why this dataset is bundled here

This dataset is cited as reference [50] in the TIG-CDO manuscript
(`paper2-solution/main_v2.md`) and is the empirical source for the FDCE / R-11 decline-code
calibration reported in Section VI.I (organic decline-code p99 = 0.712, false-positive rate
0.023%, Cohen's *d* = 7.67 versus the simulated FDCE attack). The Apache-2.0 license permits
redistribution, so — unlike the APA-DDoS dataset in this same package, whose license is
unconfirmed — this dataset is included here as data, not just as a pointer, so the FDCE
calibration in `scripts/calibrate_fdce_from_real_data.py` is fully reproducible offline.

## Attribution

Per Apache-2.0 §4, this NOTICE file and the accompanying `LICENSE` file must be preserved in
any redistribution of this dataset or derivative works of it.
