# Releasing a new version of this repository on Zenodo

This repo is already connected to Zenodo through the GitHub integration. v1.0.0 was
archived on 2026-08-19 (version DOI 10.5281/zenodo.22005892, concept DOI
10.5281/zenodo.22005891). A new GitHub release creates a new **version** under the same
concept DOI, so the manuscript's citation of 10.5281/zenodo.22005891 does not change.

## 1. Commit and push

```bash
cd /Volumes/4TB/research-data-and-code/zenado/ddos-data
git add -A
git commit -m "v1.1.0: bundle card-auth data without LFS; add testbed, scenarios, calibration outputs"
git push origin main
```

The four `data/ng-card-auth/parts/*.parquet` files are ~46 MB each: under GitHub's 100 MB hard
limit and its 50 MB warning threshold, so no LFS is needed. Do **not** re-enable LFS: Zenodo's GitHub
integration archives the source zip, which holds only LFS pointer files.

## 2. Confirm the Zenodo toggle is still on

https://zenodo.org/account/settings/github/ → `amitrangari/ddos-data` should be **On**.

## 3. Tag and release

```bash
git tag -a v1.1.0 -m "TIG-CDO replication package v1.1.0"
git push origin v1.1.0
gh release create v1.1.0 --title "v1.1.0" --notes "Bundles the card-authorization dataset as real files (v1.0.0 held only an LFS pointer); adds the Kubernetes testbed, CSDA scenarios, remaining calibration outputs, and dataset manifests."
```

## 4. Verify the archive

Zenodo mints the new version DOI within a few minutes. Then:

- Download the new zip from the Zenodo record and confirm
  `data/ng-card-auth/parts/part-000.parquet` is ~46 MB, not a 134-byte pointer.
- Check that `.zenodo.json` metadata rendered: three creators with ORCIDs, MIT license,
  11 `isDerivedFrom` identifiers.
- Optionally verify `shasum -a 256 -c SHA256SUMS` inside the unzipped folder.

## 5. After the paper is accepted

Add an `isSupplementTo` related identifier (the article DOI) to `.zenodo.json`, fill
`preferred-citation.journal`/`doi` in `CITATION.cff`, and cut v1.1.1.

## Do not automate past this point

Commit is local and reversible. Pushing, tagging, and releasing are public and effectively
irreversible (a minted DOI is permanent). Confirm each time before running steps 1–3.
