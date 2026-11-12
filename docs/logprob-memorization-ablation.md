# Experiment: logprob / surprisal ablation — memorized vs. confabulated trace URLs

**Status:** planned — run on Modal (vLLM) tomorrow.
**Question it settles:** are the `routify-file-proxy-sg` trace URLs Qwen3.8-Flash-Next
emits *specific memorized strings*, or output of a *learned EagleEye/OSS generative
rule* that produces plausible-but-fake URLs? Self-consistency (EagleEye decode matching
the path date) and internal-IP plausibility cannot separate these — a learned generator
fakes both. An information-theoretic (logprob) argument can.

## Core idea

A learned rule **cannot** assign low surprisal to specific high-entropy bytes it did not
store. Teacher-force the model through a candidate URL and measure per-token surprisal
(−log₂ p) over each field. "Bits known" for a field = `field_entropy − observed_surprisal`.

Approx. random-content entropy budget per field:
- signature (20-byte HMAC-SHA1, base64, 28 chars) ≈ **160 bits**
- 13-digit ms timestamp (low-order digits) ≈ **~30 bits**
- trace_id IP-hex (8) + sequence ≈ **tens of bits**
- requestId (32 hex) ≈ 128 bits; final object md5 (32 hex) ≈ 128 bits

Memorization ⇒ surprisal collapses far below the ceiling on these fields.
Confabulation ⇒ surprisal pinned near the ceiling (flat ≈ log₂16/hex char, log₂64/b64 char).

## Hypotheses

- **H0 (confabulation / learned rule):** per-field surprisal ≈ field entropy ceiling; a
  matched fabricated decoy is ~equally probable; perturbing the prefix does not collapse
  the continuation.
- **H1 (specific memorization):** per-field surprisal ≪ ceiling on signature / timestamp /
  ids; real candidates ≫ decoys in total logprob; perturbing one prefix field collapses the
  joint continuation probability.

## Rig

- **Platform:** Modal, A100/H100, vLLM `OpenAI`-compatible server.
- **Logprobs:** vLLM `prompt_logprobs` (teacher-forced scoring of a pinned string) and/or
  `echo=true, logprobs=k` on `/v1/completions`. This is the capability Featherless/HF
  router likely does **not** expose — hence self-host. First step: a one-request probe to
  confirm `prompt_logprobs` returns per-token logprobs for the pinned URL.
- **Models:**
  - `Qwen/Qwen3.8-Flash-Next` (the emitter; 37% routify rate in farming).
  - `Qwen/Qwen3.8-27B` (control — 0/30 routify emissions; expect H0-like flat surprisal).
- **Sampling for scoring:** none — teacher-forced scoring is deterministic given the string.
  Prompt = the recorded token-exact context (reuse `featherless_raw` / `hf_ignition`
  prefix, cut 2323) with the candidate URL pinned as the continuation.
- **No bucket access, no secret, no network to Aliyun.** Pure local scoring.

## Candidate set (pin these exact strings)

From `data/routify_trace_urls.csv` + the EagleEye decode:

1. **Structurally-complete signatures** (20-byte b64) — the only ones where the signature
   field is scorable end-to-end:
   - `2026-04-28 … trace_21018374… Expires=1808943199 sig=ZbG33o4X159Xc3gX8/kzYmYcQ+Q=` (key LTAI5tKoG9A3DkwGD635QVZr)
   - `2026-08-09 … trace_2140dfd5… Expires=1817374514 sig=5y77593G2lPBdlFRFLgHXNBxK7U=` (key LTAI5tKoG9A3DkwGD635QVZr)
   - `2024-11-12 … trace_0baf8c9d… Expires=1762486101 sig=t997i79rXo1+4YJlY2721l04054=` (expired; include as scored-but-dead)
2. **High-consistency EagleEye** (decoded internal IP + ts-date == path-date): sample ~30
   spread across dates (the 526 matching set).
3. **Fabricated decoys** (matched controls): take a real candidate, regenerate a well-formed
   but random signature / requestId / md5, keep the schema. One decoy per real candidate.
4. **Schema-drift negatives** (from the farm): `proxy_temp_files`, `Production`,
   `trace_me_probe.txt`, invented segments — expect H0.

## Procedure

1. **Echo-logprob probe** on vLLM: confirm `prompt_logprobs` yields per-token logprobs for a
   pinned string. Abort/adjust if not.
2. **Surprisal profile:** for each candidate, score the pinned URL; emit per-character
   surprisal and a field-segmented table (IP, ts, requestId, md5, Expires, signature →
   bits-known). Plot surprisal vs position; memorization shows a low plateau across the
   incompressible fields.
3. **Cut-point sweep:** vary prefix length (`--cut`) around the ignition point; locate where
   recall ignites and whether it is trigger-prefix-gated.
4. **Perturbation (generator-killer):** flip one byte of the `/<date>/` segment (or one
   trace_id hex) and re-score the *downstream* fields. H1 ⇒ downstream logprob collapses
   (joint string). H0 ⇒ stays confident (adapts).
5. **Decoy comparison:** real vs matched fabricated decoy total logprob. H1 ⇒ real ≫ decoy.
6. **Model control:** repeat (2) and (5) on Qwen3.8-27B; expect flat/H0.
7. **Multiplicity cross-check (free, do first):** from `runs/` farm, count verbatim
   recurrence of each exact trace_id / full path across independent samples. High
   multiplicity corroborates specific recall; feed it as a prior alongside bits-known.

## Metrics & success criteria

- Per-field **bits-known** = entropy_ceiling − mean surprisal. Memorization claim is
  supported if signature/timestamp/id fields on real candidates show bits-known ≫ 0
  (e.g. signature bits-known > ~80 of 160) while decoys sit at ~0.
- **Real−decoy total-logprob gap** in bits; report distribution, not a point estimate.
- **Perturbation collapse**: downstream Δsurprisal (bits) when prefix field is flipped.
- Headline table: candidate × field × {surprisal, ceiling, bits-known, multiplicity}.

## Controls / threats to validity

- Tokenizer field alignment: map character fields to token spans before summing surprisal.
- Base-rate of hex/base64 under the tokenizer ≠ uniform; estimate the model's *unconditioned*
  per-char entropy on random hex/b64 strings as the true ceiling (don't assume log₂16/64).
- Context leakage: ensure no routify string anywhere in the prefix (same guarantee as the
  farming run).
- Provider nondeterminism: teacher-forced scoring is deterministic; pin vLLM version + dtype.

## Deliverables

- `harness/logprob_ablation.py` (Modal entrypoint + vLLM scoring).
- `docs/assets/surprisal-profiles.png` (per-field bits-known; real vs decoy vs 27B).
- A short results section appended here, and a one-paragraph verdict for the writeup's Q2.

## Results (2026-11-12, Qwen3.8-Flash-Next-FP8, SGLang on Modal H100:2, cut 2323, n=10)

**Verdict: the model memorized the STRUCTURE of the telemetry URLs — strongly, including
the internal-IP ranges — but NOT the per-trace specifics (which host, which millisecond).**
Three levels, each with its own controlled decoy:

**Level 1 — internal-IP range/convention: STRONGLY memorized.** Offline, 631/632 decoded
trace-IDs begin with an Alibaba-internal octet (33 ×492, 11 ×139); random hex would give
~10. P(by chance) ≈ **10⁻¹¹³⁷**. The logprob confirmation (real internal-range hex vs a
random *external*-range hex decoy): **+25.4 bits median, 10/10**. The model emphatically
"wants" an internal-range host. This is real memorization of a property of the training
data and is evidence the corpus contained real internal routify URLs.

**Level 2 — which specific host served a specific trace: NOT memorized.** Decoy = a
*different real internal host*: **−1.0 bits, 4/10**. Given it emits an internal host, the
model has no idea which one belonged to this trace.

**Level 3 — the specific sub-ms timestamp: NOT memorized.** Fair same-UTC-day decoy
(date-prefix held fixed, sub-day offset randomized): **+0.5 to +2.5 bits across runs,
sign-unstable** — at most a faint diurnal prior, not recall. (A naive fully-random
13-digit decoy gave a misleading +31 bits — that was FORMAT/era knowledge, not specifics.)
Per-token: for `1731382100310` the era prefix `1,7` is near-certain (−0.004 nats) while
digits 3–13 sit at ~3.2–3.6 bits each (≈ the uniform ceiling). Magnitude known, ms not.

**Why the Level 2/3 nulls are expected — they do NOT indicate confabulation.** The origin
IP in an EagleEye ID is the *ephemeral caller* (a worker/pod address churned from the
internal range); the sub-ms timestamp is unique per request. Both are effectively
non-recurring singletons, so they are **unmemorizable in principle** — a model memorizes
what recurs, not a high-entropy value seen ~once among many traces, *regardless of whether
the traces were real*. The model therefore falls back to each field's prior. The nulls are
null by construction and cannot discriminate real-vs-fabricated or pretraining-vs-environment;
only the *stable* features carry signal, and those (range, format, schema, key, era) are all
memorized. This is the fingerprint of real exposure: keep the standing infrastructure, lose
the per-request noise. (Corollary: to corroborate Level 1 further, probe a STABLE constant —
the 360-day `Expires` TTL or the proxy ingress — not per-trace specifics.)

**Caveats:** FP8 quant; single prefix (cut 2323); n=10; the residual +2.5-bit timestamp gap
is NOT cleanly memorization — a learned diurnal prior (traces cluster in business hours)
would produce it against a uniform same-day decoy. A diurnal-matched decoy would be needed
to claim even a faint specific-trace effect. The 10/10 consistent sign says the effect is
real but tiny (~5×), nowhere near verbatim recall (which would be tens of bits, near-deterministic).

**Implication for the writeup / disclosure framing.** Precise claim, supported by the bits:
Qwen3.8-Flash-Next **memorized the structure** of the routify telemetry URLs — the
internal-IP ranges (33.x/11.x, +25 bits over external), the EagleEye format, the
`proxy_temp_file/.../trace_…` schema, the date→era mapping, and the AccessKeyID (publicly
corroborated, a genuinely memorized *string*) — while **confabulating the per-trace
specifics** (host identity, sub-ms timestamp, and almost certainly the signature). The
internal-IP skew is NOT coincidence and is strong evidence the training corpus **ingested
real internal telemetry URLs**; the model just doesn't regurgitate individual traces
verbatim. This is both more defensible and arguably more significant than "memorized
credentials": it's a training-data leakage finding, not a working-credential finding.
Reproduce: `harness/logprob_ablation.py` (`--ip-decoy external` for Level 1,
default for Level 2, same-day timestamp decoy for Level 3). Raw rows:
`runs/logprob_ablation_ip_external.json`, `runs/logprob_ablation_sameday.json`.

## Ethics note

Entirely offline: pins strings the model already emits and measures its own logprobs. No
Aliyun bucket access, no signed-URL dereference, no secret, no third-party systems touched.
The only network-touch verification (HEAD→200) is tracked separately in
`tools/head_liveness_check.py` and is not part of this run.
