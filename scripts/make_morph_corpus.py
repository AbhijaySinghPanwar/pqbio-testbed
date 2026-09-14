"""Generate a morph corpus from LFW (PROJECT_SPEC.md §5.4 D2, §6's "generate rather than
collect" fallback).

Owner: Krish

FRLL-Morphs and SMDD both need agreements this project does not have (`data/LICENCES.md`).
A morph corpus is the one attack corpus that can be *generated* rather than collected —
which is exactly SMDD's own premise — provided a source of contributing faces exists. LFW
supplies those: no EULA, no fee, no request form. What LFW does **not** supply is
redistribution rights (its images are press photographs whose copyright sits with the
original outlets), so nothing this script produces is committed. Manifest only; see
`data/LICENCES.md` for the reasoning.

**Two morph methods**, so the detector cannot learn one tool's artefacts and call it
morph detection:

1. `landmark_alpha` — the plain case. Delaunay-triangulate both faces on shared landmarks,
   warp each to the mean shape, alpha-blend at 0.5. Every pixel is a blend of two faces.
2. `spliced_jpeg` — the hard case, and the one that matches what real morph attacks do.
   Blend asymmetrically (0.6 toward the first contributor), then **splice the morphed face
   region back into that contributor's own untouched background** through a feathered
   convex-hull mask, then re-compress as JPEG. Only the face interior is blended; the
   hair, ears, neck, shoulders and background are one real photograph. Cheap global cues —
   whole-image blending statistics, doubled compression over the entire frame — do not
   survive this, which is why cross-method generalisation between the two is the honest
   number to report (§12).

**Landmarks: 5, not 68.** `pqbio.detect.face`'s SCRFD is the project's only face detector
and this script reuses it rather than adding a second one. SCRFD emits five keypoints
(eye centres, nose tip, mouth corners); the triangulation augments them with the face
box's own corners and edge midpoints and the image corners, giving a coarse but genuine
piecewise-affine warp. Published morph corpora use 68 or 81 points and produce visibly
smoother morphs — a real limitation, recorded in §12, not a detail.

**Pair selection: mutual nearest neighbours in ArcFace embedding space.** A morph is only
a threat when it plausibly passes for both contributors, so pairing must be non-random or
the detector learns "implausible pair" instead of "morph". The obvious criterion —
matching apparent sex and face shape — needs demographic labels this corpus does not have
and that we will not infer with a classifier we cannot validate. Embedding similarity is
a better criterion anyway: it is exactly what an attacker optimises when choosing an
accomplice, it is measurable, and it needs no protected attribute. Each identity is paired
with its most similar *other* identity above `MIN_PAIR_COSINE`, mutual pairs preferred,
and every pair's similarity is recorded in the manifest so the plausibility of the corpus
can be audited rather than asserted.

**Splits are subject-disjoint by construction**: identities are partitioned *before*
pairing, pairs are formed only within a partition, and bona fide images are drawn only
from the partition's own identities. No identity contributes to a morph in one split and
appears in another, as contributor or bona fide. Asserted, not assumed.

Usage:
    python scripts/make_morph_corpus.py
    python scripts/make_morph_corpus.py --max-identities 60 --out data/processed/morph_corpus
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import cv2
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from pqbio.bench._common import run_metadata  # noqa: E402

SEED = 2026
# Minimum ArcFace cosine between two identities' mean embeddings for the pair to count as
# plausible. Not a tuned value: it is the 75th percentile of the observed between-identity
# similarity distribution, computed at run time and recorded in the manifest, so "the most
# similar quarter of available pairings" is the criterion rather than a magic constant.
PAIR_PERCENTILE = 75.0
BLEND_PLAIN = 0.5
BLEND_SPLICED = 0.6
SPLICED_JPEG_QUALITY = 75
METHODS = ("landmark_alpha", "spliced_jpeg")
# Contributing image, enrolment (bona fide) image, D-MAD live reference -- one each.
IMAGES_PER_IDENTITY = 3


# ----------------------------------------------------------------------------------
# Landmarks and warping
# ----------------------------------------------------------------------------------


def _control_points(
    kps: np.ndarray, box: tuple[int, int, int, int], shape: tuple[int, int]
) -> np.ndarray:
    """SCRFD's 5 keypoints plus the face box's and image's corners and edge midpoints.

    The extra points are not landmarks in any anatomical sense; they exist so Delaunay
    triangulation covers the whole frame. Without them the warp is defined only inside the
    convex hull of five points and the rest of the image tears.
    """
    h, w = shape
    x, y, bw, bh = box
    x2, y2 = x + bw, y + bh
    frame = np.array(
        [
            [0, 0],
            [w // 2, 0],
            [w - 1, 0],
            [0, h // 2],
            [w - 1, h // 2],
            [0, h - 1],
            [w // 2, h - 1],
            [w - 1, h - 1],
            [x, y],
            [x2 - 1, y],
            [x, y2 - 1],
            [x2 - 1, y2 - 1],
            [(x + x2) // 2, y],
            [(x + x2) // 2, y2 - 1],
            [x, (y + y2) // 2],
            [x2 - 1, (y + y2) // 2],
        ],
        dtype=np.float32,
    )
    return np.vstack([kps.astype(np.float32), frame])


def _delaunay_triangles(points: np.ndarray, shape: tuple[int, int]) -> list[tuple[int, int, int]]:
    h, w = shape
    subdiv = cv2.Subdiv2D((0, 0, w, h))
    for p in points:
        subdiv.insert((float(np.clip(p[0], 0, w - 1)), float(np.clip(p[1], 0, h - 1))))
    lookup = {(round(float(p[0])), round(float(p[1]))): i for i, p in enumerate(points)}
    triangles: list[tuple[int, int, int]] = []
    for t in subdiv.getTriangleList():
        idx = []
        for k in range(3):
            key = (round(float(t[2 * k])), round(float(t[2 * k + 1])))
            if key in lookup:
                idx.append(lookup[key])
        if len(idx) == 3:
            triangles.append((idx[0], idx[1], idx[2]))
    return triangles


def _warp_triangle(src: np.ndarray, dst: np.ndarray, t_src: np.ndarray, t_dst: np.ndarray) -> None:
    """Piecewise-affine warp of one triangle from `src` into `dst`, in place."""
    r_src = cv2.boundingRect(np.asarray([t_src], dtype=np.float32))
    r_dst = cv2.boundingRect(np.asarray([t_dst], dtype=np.float32))
    if r_src[2] <= 0 or r_src[3] <= 0 or r_dst[2] <= 0 or r_dst[3] <= 0:
        return

    t_src_off = np.asarray([[p[0] - r_src[0], p[1] - r_src[1]] for p in t_src], dtype=np.float32)
    t_dst_off = np.asarray([[p[0] - r_dst[0], p[1] - r_dst[1]] for p in t_dst], dtype=np.float32)

    src_patch = src[r_src[1] : r_src[1] + r_src[3], r_src[0] : r_src[0] + r_src[2]]
    if src_patch.size == 0:
        return
    matrix = cv2.getAffineTransform(t_src_off, t_dst_off)
    warped = cv2.warpAffine(
        src_patch,
        matrix,
        (r_dst[2], r_dst[3]),
        flags=cv2.INTER_LINEAR,
        borderMode=cv2.BORDER_REFLECT_101,
    )
    mask = np.zeros((r_dst[3], r_dst[2], 3), dtype=np.float32)
    cv2.fillConvexPoly(mask, t_dst_off.astype(np.int32), (1.0, 1.0, 1.0), 16, 0)

    region = dst[r_dst[1] : r_dst[1] + r_dst[3], r_dst[0] : r_dst[0] + r_dst[2]]
    if region.shape[:2] != mask.shape[:2]:
        return
    region *= 1.0 - mask
    region += warped.astype(np.float32) * mask


def _warp_to_shape(
    image: np.ndarray,
    src_points: np.ndarray,
    dst_points: np.ndarray,
    triangles: list[tuple[int, int, int]],
) -> np.ndarray:
    out = np.zeros_like(image, dtype=np.float32)
    for a, b, c in triangles:
        _warp_triangle(
            image.astype(np.float32),
            out,
            np.array([src_points[a], src_points[b], src_points[c]]),
            np.array([dst_points[a], dst_points[b], dst_points[c]]),
        )
    return np.clip(out, 0, 255).astype(np.uint8)


def morph_pair(
    img_a: np.ndarray, pts_a: np.ndarray, img_b: np.ndarray, pts_b: np.ndarray, alpha: float
) -> np.ndarray:
    """Warp both faces to the shape-mean and blend. `alpha` weights the FIRST contributor."""
    shape = img_a.shape[:2]
    mean_pts = (alpha * pts_a + (1.0 - alpha) * pts_b).astype(np.float32)
    triangles = _delaunay_triangles(mean_pts, shape)
    warped_a = _warp_to_shape(img_a, pts_a, mean_pts, triangles)
    warped_b = _warp_to_shape(img_b, pts_b, mean_pts, triangles)
    blended = alpha * warped_a.astype(np.float32) + (1.0 - alpha) * warped_b.astype(np.float32)
    return np.clip(blended, 0, 255).astype(np.uint8)


def splice_into_background(
    morphed: np.ndarray, host: np.ndarray, kps_host: np.ndarray, jpeg_quality: int
) -> np.ndarray:
    """Paste the morphed face interior back into `host`'s untouched photograph.

    This is what a real morph attack looks like: only the region a passport photo's face
    occupies is synthetic, and everything else — hair, ears, neck, background, and the
    whole image's original compression history — belongs to one real person. A detector
    keying on global blending statistics finds nothing here.
    """
    hull = cv2.convexHull(kps_host.astype(np.int32))
    centre = tuple(int(v) for v in np.mean(kps_host, axis=0))
    mask: np.ndarray = np.zeros(host.shape[:2], dtype=np.uint8)
    # Dilate beyond the 5-point hull, which is tight around eyes/nose/mouth, so the
    # spliced region actually covers the face rather than a small central patch.
    cv2.fillConvexPoly(mask, hull, 255)
    radius = int(0.9 * max(np.ptp(kps_host[:, 0]), np.ptp(kps_host[:, 1])))
    cv2.circle(mask, centre, max(radius, 10), 255, -1)
    mask = cv2.GaussianBlur(mask, (31, 31), 0)

    alpha = (mask.astype(np.float32) / 255.0)[:, :, None]
    composited = alpha * morphed.astype(np.float32) + (1 - alpha) * host.astype(np.float32)
    composited = np.clip(composited, 0, 255).astype(np.uint8)

    ok, buf = cv2.imencode(".jpg", composited, [cv2.IMWRITE_JPEG_QUALITY, jpeg_quality])
    if not ok:
        raise RuntimeError("JPEG re-encode failed")
    decoded = cv2.imdecode(buf, cv2.IMREAD_COLOR)
    return np.asarray(decoded, dtype=np.uint8)


# ----------------------------------------------------------------------------------
# Corpus assembly
# ----------------------------------------------------------------------------------


def _lfw_root() -> Path:
    """sklearn's LFW funneled cache, downloading the archive once if it is absent.

    The download goes through `fetch_lfw_people` with a filter that admits almost nothing
    (`min_faces_per_person=70`, `resize=0.1`): the archive is fetched and extracted whole,
    but only a few hundred thumbnails are decoded into memory. Loading the pool itself
    through that API is what this replaced -- it materialises every selected image as
    float32 at once, ~6.9 GB for the >=2-image pool.
    """
    from sklearn.datasets import fetch_lfw_people, get_data_home

    root = Path(get_data_home()) / "lfw_home" / "lfw_funneled"
    if not root.is_dir():
        fetch_lfw_people(min_faces_per_person=70, resize=0.1, funneled=True)
    if not root.is_dir():
        raise FileNotFoundError(f"LFW funneled cache not found at {root} after download")
    return root


def _load_lfw(
    max_identities: int | None, min_faces: int
) -> tuple[list[str], dict[str, list[np.ndarray]], dict[str, int]]:
    """Up to `IMAGES_PER_IDENTITY` images for every identity with >= `min_faces` images.

    Returns the identities, their images (BGR uint8, 250x250), and a census of the source
    so the manifest can state how much of LFW the pool actually covers.
    """
    root = _lfw_root()
    per_identity: dict[str, list[Path]] = {}
    for directory in sorted(d for d in root.iterdir() if d.is_dir()):
        files = sorted(directory.glob("*.jpg"))
        if files:
            per_identity[directory.name.replace("_", " ")] = files

    census = {
        "lfw_identities_total": len(per_identity),
        "lfw_images_total": sum(len(f) for f in per_identity.values()),
        "lfw_identities_with_1_image": sum(len(f) == 1 for f in per_identity.values()),
        "lfw_identities_with_2plus_images": sum(len(f) >= 2 for f in per_identity.values()),
        "lfw_identities_with_3plus_images": sum(len(f) >= 3 for f in per_identity.values()),
    }

    names = [n for n, files in per_identity.items() if len(files) >= min_faces]
    if max_identities is not None:
        names = names[:max_identities]

    by_identity: dict[str, list[np.ndarray]] = {}
    for name in names:
        images = []
        for path in per_identity[name][:IMAGES_PER_IDENTITY]:
            image = cv2.imread(str(path), cv2.IMREAD_COLOR)
            if image is not None:
                images.append(np.asarray(image, dtype=np.uint8))
        by_identity[name] = images
    return names, by_identity, census


def _detect(image: np.ndarray) -> tuple[np.ndarray, tuple[int, int, int, int], np.ndarray] | None:
    """(5 keypoints, face box, ArcFace embedding) or None when SCRFD finds no face."""
    from pqbio.detect.face import _get_app

    faces = _get_app().get(image)
    if not faces:
        return None
    face = max(faces, key=lambda f: float(f.det_score))
    if face.kps is None or face.normed_embedding is None:
        return None
    x1, y1, x2, y2 = (int(v) for v in face.bbox)
    box = (max(x1, 0), max(y1, 0), max(x2 - x1, 1), max(y2 - y1, 1))
    return np.asarray(face.kps, dtype=np.float32), box, np.asarray(face.normed_embedding)


def build_corpus(out_dir: Path, max_identities: int | None, min_faces: int) -> dict[str, Any]:
    rng = np.random.default_rng(SEED)
    names, by_identity, census = _load_lfw(max_identities, min_faces)
    print(f"loaded {len(names)} identities (of {census['lfw_identities_total']})", file=sys.stderr)

    # Roles per identity, and why the pool floor is two images rather than one:
    #
    #   reference       the image the morph is built from
    #   bona_fide       a DIFFERENT genuine image: the enrolment template for MMPMR, and
    #                   the genuine sample the detectors must not flag
    #   live_reference  a third image, D-MAD's trusted live capture -- optional
    #
    # A one-image identity cannot supply `bona_fide` without reusing `reference`, and then
    # MMPMR would ask whether a morph matches the very photograph it was made from, which
    # inflates exactly the number this corpus exists to measure. 4,069 of LFW's 5,749
    # identities have a single image, so that -- not compute -- is what bounds the pool.
    #
    # `live_reference` is optional because requiring it would halve the pool (901 of LFW's
    # identities have >=3 images). D-MAD is evaluated only on rows whose presenting
    # identity has one; `morph_eval` records how many rows that drops.
    profiles: dict[str, dict[str, Any]] = {}
    for index, name in enumerate(names):
        if index % 200 == 0:
            print(f"  detecting: {index}/{len(names)}", file=sys.stderr)
        detected = [(img, _detect(img)) for img in by_identity[name]]
        usable = [(img, d) for img, d in detected if d is not None]
        if len(usable) < 2:
            continue
        ref_img, (ref_kps, ref_box, ref_emb) = usable[0]
        bona_img, _ = usable[1]
        profiles[name] = {
            "reference": ref_img,
            "kps": ref_kps,
            "box": ref_box,
            "embedding": ref_emb,
            "bona_fide": bona_img,
            "live_reference": usable[2][0] if len(usable) >= 3 else None,
        }
    usable_names = sorted(profiles)
    with_live = sum(1 for n in usable_names if profiles[n]["live_reference"] is not None)
    print(
        f"{len(usable_names)} identities usable (>=2 detected faces); {with_live} also have a "
        "live reference",
        file=sys.stderr,
    )

    # --- subject-disjoint partition, BEFORE any pairing --------------------------------
    shuffled = list(usable_names)
    rng.shuffle(shuffled)
    cut = int(0.6 * len(shuffled))
    split_of = {n: ("train" if i < cut else "test") for i, n in enumerate(shuffled)}

    # --- pair selection: highest ArcFace cosine, within a split ------------------------
    # Cosine is between the two CONTRIBUTING images' embeddings -- the images that actually
    # get blended -- not identity means. Vectorised: 1.4M pairs at the full >=2-image pool.
    matrix = np.stack([profiles[n]["embedding"] for n in usable_names]).astype(np.float32)
    all_sims = matrix @ matrix.T
    upper = np.triu_indices(len(usable_names), k=1)
    between_identity = all_sims[upper]
    pair_floor = float(np.percentile(between_identity, PAIR_PERCENTILE))
    index_of = {n: i for i, n in enumerate(usable_names)}

    pairs: list[tuple[str, str, float]] = []
    used: set[str] = set()
    for split in ("train", "test"):
        members = [n for n in usable_names if split_of[n] == split]
        idx = np.array([index_of[n] for n in members])
        sub = all_sims[np.ix_(idx, idx)]
        rows_i, cols_i = np.triu_indices(len(members), k=1)
        values = sub[rows_i, cols_i]
        order = np.argsort(-values, kind="stable")
        for k in order:
            sim = float(values[k])
            if sim < pair_floor:
                break
            a, b = members[rows_i[k]], members[cols_i[k]]
            if a in used or b in used:
                continue
            # The first contributor is the one presenting at the desk: their background is
            # kept by `spliced_jpeg`, and D-MAD compares against their live capture. Put
            # the identity that has one first whenever only one of the two does.
            if profiles[a]["live_reference"] is None and profiles[b]["live_reference"] is not None:
                a, b = b, a
            pairs.append((a, b, sim))
            used.update({a, b})

    # --- generate ----------------------------------------------------------------------
    out_dir.mkdir(parents=True, exist_ok=True)
    samples: list[dict[str, Any]] = []

    for a, b, sim in pairs:
        split = split_of[a]
        pa, pb = profiles[a], profiles[b]
        pts_a = _control_points(pa["kps"], pa["box"], pa["reference"].shape[:2])
        pts_b = _control_points(pb["kps"], pb["box"], pb["reference"].shape[:2])

        for method in METHODS:
            if method == "landmark_alpha":
                image = morph_pair(pa["reference"], pts_a, pb["reference"], pts_b, BLEND_PLAIN)
            else:
                blended = morph_pair(pa["reference"], pts_a, pb["reference"], pts_b, BLEND_SPLICED)
                image = splice_into_background(
                    blended, pa["reference"], pa["kps"], SPLICED_JPEG_QUALITY
                )
            rel = f"{split}/morph_{method}/{a.replace(' ', '_')}__{b.replace(' ', '_')}.png"
            path = out_dir / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            cv2.imwrite(str(path), image)
            samples.append(
                {
                    "path": rel,
                    "label": "morph",
                    "method": method,
                    "split": split,
                    "contributors": [a, b],
                    "pair_cosine": sim,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )

    for name in usable_names:
        split = split_of[name]
        # `live_reference` is written as a sample so the manifest records it, but it is a
        # reference rather than something to be classified -- morph_eval excludes it from
        # the detection pool and uses it only as D-MAD's trusted capture.
        for kind in ("bona_fide", "live_reference"):
            if profiles[name][kind] is None:
                continue
            rel = f"{split}/{kind}/{name.replace(' ', '_')}.png"
            path = out_dir / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            cv2.imwrite(str(path), profiles[name][kind])
            samples.append(
                {
                    "path": rel,
                    "label": kind,
                    "method": None,
                    "split": split,
                    "contributors": [name],
                    "pair_cosine": None,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )

    # --- the disjointness claim, asserted rather than asserted-in-prose ----------------
    identities_by_split: dict[str, set[str]] = {"train": set(), "test": set()}
    for s in samples:
        identities_by_split[s["split"]].update(s["contributors"])
    overlap = identities_by_split["train"] & identities_by_split["test"]
    if overlap:
        raise AssertionError(f"splits are not subject-disjoint: {sorted(overlap)}")

    return {
        **run_metadata(seed=SEED),
        "source_dataset": "LFW (funneled, 250x250), read from sklearn's cache "
        "(sklearn.datasets.get_data_home()/lfw_home/lfw_funneled)",
        "pool": {
            **census,
            "min_faces_per_identity": min_faces,
            "max_identities": max_identities,
            "images_read_per_identity": IMAGES_PER_IDENTITY,
            "identities_usable": len(usable_names),
            "identities_with_live_reference": with_live,
            "why_this_pool": (
                "every LFW identity with >=2 images. The bound is LFW's structure, not "
                "compute: a one-image identity cannot supply an enrolment image distinct "
                "from the image its morph is built from, so MMPMR on it would match a "
                "morph against its own source photograph. Identities with >=2 images but "
                "no detectable face on two of them are dropped by SCRFD"
            ),
        },
        "source_licence": "see data/LICENCES.md -- no EULA; images NOT redistributable, "
        "so this corpus is regenerated, never committed",
        "landmark_source": "pqbio.detect.face SCRFD 5-point keypoints (no second detector)",
        "methods": list(METHODS),
        "blend_plain": BLEND_PLAIN,
        "blend_spliced": BLEND_SPLICED,
        "spliced_jpeg_quality": SPLICED_JPEG_QUALITY,
        "pair_selection": {
            "criterion": "highest ArcFace cosine between the two contributing images' "
            "embeddings (the images that are blended, not identity means), greedily "
            "matched within a split, each identity used at most once",
            "rationale": "a morph is only a threat if it plausibly passes for both "
            "contributors; embedding similarity is what an attacker optimises when "
            "choosing an accomplice, is measurable, and needs no demographic labels this "
            "corpus does not have",
            "percentile_floor": PAIR_PERCENTILE,
            "cosine_floor": pair_floor,
            "between_identity_cosine_median": float(np.median(between_identity)),
            "n_pairs": len(pairs),
            "chosen_pair_cosine": (
                {
                    "max": float(np.max([c for _, _, c in pairs])),
                    "p90": float(np.percentile([c for _, _, c in pairs], 90)),
                    "p75": float(np.percentile([c for _, _, c in pairs], 75)),
                    "median": float(np.median([c for _, _, c in pairs])),
                    "p25": float(np.percentile([c for _, _, c in pairs], 25)),
                    "min": float(np.min([c for _, _, c in pairs])),
                }
                if pairs
                else None
            ),
        },
        "splits": {
            "policy": "identities partitioned before pairing; pairs and bona fide drawn "
            "only within a partition; asserted subject-disjoint at generation time",
            "train_identities": sorted(identities_by_split["train"]),
            "test_identities": sorted(identities_by_split["test"]),
        },
        "counts": {
            "identities_usable": len(usable_names),
            "morphs": sum(1 for s in samples if s["label"] == "morph"),
            "bona_fide": sum(1 for s in samples if s["label"] == "bona_fide"),
            "live_reference": sum(1 for s in samples if s["label"] == "live_reference"),
            "by_method": {m: sum(1 for s in samples if s["method"] == m) for m in METHODS},
        },
        "samples": samples,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", type=Path, default=REPO_ROOT / "data" / "processed" / "morph_corpus"
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=REPO_ROOT / "data" / "manifests" / "morph_corpus_manifest.json",
    )
    parser.add_argument(
        "--max-identities",
        type=int,
        default=None,
        help="cap the pool (default: every eligible LFW identity)",
    )
    parser.add_argument(
        "--min-faces",
        type=int,
        default=2,
        help="minimum LFW images per identity; below 2 MMPMR self-matches",
    )
    args = parser.parse_args()

    manifest = build_corpus(args.out, args.max_identities, args.min_faces)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    c = manifest["counts"]
    print(
        f"\nidentities={c['identities_usable']} morphs={c['morphs']} "
        f"bona_fide={c['bona_fide']} by_method={c['by_method']}\n"
        f"pair cosine floor={manifest['pair_selection']['cosine_floor']:.3f} "
        f"(median between-identity {manifest['pair_selection']['between_identity_cosine_median']:.3f})\n"
        f"wrote {args.manifest}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
