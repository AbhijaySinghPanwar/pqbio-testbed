# Dataset licence status

Required by PROJECT_SPEC.md §6 ("Record licence status in `data/LICENCES.md`"). One row
per dataset the project uses or intends to use, with what was actually verified and what
was not.

_Last reviewed: 2026-09-14._

---

## In use

### LFW — Labeled Faces in the Wild (contributing faces for the morph corpus)

> **⚠ OUTSTANDING — terms not verified from the primary source.** Everything below about
> LFW's terms comes from secondary sources. The canonical page
> (`http://vis-www.cs.umass.edu/lfw/`) could not be read: that host does not resolve from
> the environment this was written in, while the rest of the network does. This entry is
> **not settled** and should be closed by someone who can reach the primary page and
> replace the "Terms" paragraph with its verbatim notice. The commit policy is set
> conservatively *because* this is open.

| | |
|---|---|
| **Terms verified from primary source** | **No — outstanding** (primary host unreachable; see banner) |
| **Signed EULA / agreement required** | No, per every secondary source consulted — unconfirmed at source |
| **Fees or access request** | None, per the same sources |
| **Obtained via** | Archive downloaded once by `sklearn.datasets.fetch_lfw_people` (figshare mirror) into sklearn's data home, **outside this repository**; `scripts/make_morph_corpus.py` reads the extracted files from there |
| **Used for** | Contributing face images for the self-generated morph corpus (§5.4 D2) |
| **Committed to this repo** | **No — script and manifest only.** See "Commit policy" below. |
| **Citation** | Huang, Ramesh, Berg & Learned-Miller, *Labeled Faces in the Wild: A Database for Studying Face Recognition in Unconstrained Environments*, UMass Amherst Technical Report 07-49, October 2007. |

**Terms, and how confident we are in them.** LFW is distributed without a formal licence
and without any signed agreement: there is no EULA, no request form, and no fee. The
consistent statement across the distributing ecosystem is that **the copyright in the
underlying photographs remains with the news outlets the images were originally
published by** — LFW is a collection of press photographs harvested from the web, not
originally-licensed material — and that users are asked to cite the technical report.

**What was not verified, stated plainly.** The canonical page
(`http://vis-www.cs.umass.edu/lfw/`) **could not be read from this environment** — that
host does not resolve here, while the rest of the network does. The terms above are
therefore taken from the distributing ecosystem (scikit-learn's loader and documentation,
the Kaggle mirror, TensorFlow Datasets' catalogue entry) rather than quoted from the
primary source. That is enough to establish *no agreement is required* — which is the
question that would have stopped this work — but it is **not** enough to treat as a
positive grant of redistribution rights, and the commit policy below is set accordingly.
Anyone able to reach the primary page should replace this paragraph with the verbatim
notice.

**Commit policy: generation script and manifest only. No images, no morphs.**

The morphs are derivative works of press photographs whose copyright sits with third
parties. "No licence" is not "permissively licensed" — it means nothing grants us
redistribution rights, so we do not take any. This also matches `data/`'s existing
convention (`.gitignore`: `data/raw/`, `data/processed/`), under which every corpus is
regenerated rather than committed and only manifests are tracked.

Concretely:

- `scripts/make_morph_corpus.py` — **committed**.
- `data/manifests/morph_corpus_manifest.json` — **committed** (identities, pair
  assignments, split membership, per-sample SHA-256, generation parameters). It records
  provenance and makes the corpus reproducible; it contains no image data.
- `data/processed/morph_corpus/` — **gitignored**, regenerated on demand.
- The LFW source images never enter the repository at all: they stay in sklearn's data
  home (`sklearn.datasets.get_data_home()/lfw_home/`).

A reader who wants the corpus runs the script; a reviewer who wants to check what we did
reads the manifest.

---

## Blocked — no licence obtained

None of these were available in time; every metric depending on them is marked BLOCKED in
`results/BLOCKERS.md` rather than estimated. §6's fallback ("if licences are delayed,
proceed with … and state clearly which datasets were unavailable") is what this table is.

| Dataset | Attack | Status |
|---|---|---|
| CASIA-FASD | Presentation | Signed academic EULA required — not obtained |
| Replay-Attack | Presentation, Replay | Signed academic EULA required — not obtained |
| OULU-NPU | Presentation | Signed academic EULA + institutional sign-off — not obtained |
| CelebA-Spoof | Presentation | Request form required — not obtained |
| FRLL-Morphs | Morphing | Signed academic EULA required — not obtained. Superseded for this session by the self-generated corpus above, which is **not** a substitute for comparison purposes (§12). |
| SMDD | Morphing | Request required — not obtained. The self-generated corpus is this project's equivalent of SMDD's approach (generate rather than collect), not of SMDD itself. |
| FaceForensics++ | Deepfake | Signed academic EULA required — not obtained |
| Celeb-DF-v2 | Deepfake | Signed academic EULA required — not obtained |
| MSU-MFSD | Replay | Signed academic EULA required — not obtained |

---

## Self-generated — no third-party licence involved

| Corpus | Notes |
|---|---|
| Injection corpus (`scripts/make_injection_corpus.py`) | Synthetic frames generated by this project. No third-party material. Manifest committed, images gitignored. |
| Morph corpus (`scripts/make_morph_corpus.py`) | Morphs are generated by this project, but the **contributing faces are LFW** — so the third-party copyright above applies to the outputs. Treated as LFW-derived, not as clean-room synthetic. |

---

## Human-subject recording

Not undertaken. §6 requires written consent and supervisor approval for any team
recording of human subjects; neither has been obtained, which is the standing blocker on
the replay corpus and on B6's operating-point characterisation (see
`results/BLOCKERS.md`).
