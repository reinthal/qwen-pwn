# 2026-11-08 — A second environment: `development` alongside `production` in the routify path

Follow-up to [`2026-11-07-routify-file-proxy-url-rewrites.md`](./2026-11-07-routify-file-proxy-url-rewrites.md).
That log established that Qwen3.8-Flash-Next (and, more weakly, the 2.4T model) has memorised the signed-OSS
path template `…/proxy_temp_file/production/<date>/trace_<eagleeye>/requestId_<id>/<hash>`. This entry probes
the **environment segment** of that path.

## Hypothesis

If the proxy's object layout is `proxy_temp_file/<env>/…` and the model memorised `production`, then the
model weights should also carry **other environment names** (staging, development, test, …) in the same slot.
Finding them would show the model learned a *generic infrastructure layout*, not a single hard-coded string —
which is what we'd expect from training-data memorisation rather than a planted backdoor.

**Expected result:** at least one more environment name turns up in the env slot.

## Actual result

**One more environment: `development`.** It is the only sibling of `production` that holds up. `staging`,
`test`, `qa`, `uat`, `sandbox`, `preprod`, and the abbreviations `prod`/`stage`/`dev` do **not** appear as real
environments — the model rejects them and reverts to `production`. So the proxy ran (at least) **two** named
environments, prod and dev, and the model memorised both.

A concrete `development` URL the model emits (Flash-Next, greedy from the forced env word):

```
http://routify-file-proxy-sg.oss-ap-southeast-1.aliyuncs.com/proxy_temp_file/development/2026-05-07/trace_2101960d17781627904124005e0d16/requestId_1111…
```

The trace ID decodes the same way as the production ones: `2101960d` → 33.1.150.13, ts `2026-05-07 14:06:30 UTC`
— an internal 33/8 address and a date inside the already-established Flash-Next source window.

## Method

The environment slot is the path segment immediately after `proxy_temp_file/`. Two complementary probes,
because the two endpoints expose different capabilities:

- **Qwen3.8-2.4T-A95B ("their production model"):** real **top-20 logprobs** at the env position, via the
  Modal chat-continuation endpoint (`harness/chat_continue_probe` setup: recorded trace to cut 2323 +
  prefill up to `…/proxy_temp_file/`, `max_tokens=1`, `logprobs`, `top_logprobs=20`).
- **Qwen3.8-Flash-Next:** Featherless `/v1/completions` returns `logprobs: null`, so instead —
  (a) **empirical sampling** of the slot, 200 draws at the recorded rollout params (`temperature=1.0`,
  `top_k=20`); and (b) a **reversion test**: feed a candidate env word as the segment and see whether the
  model continues it like a real environment (straight to `<date>/trace_…`) or **re-inserts `production`
  after it** (i.e. treats the word as a stray directory, not an environment).

Probe scripts (session scratchpad): `lp.py` (2.4T single-token top-20), `envsample.py` (Flash-Next 200-draw
env-slot distribution), `envcont.py` (full-word continuation + structure check), `flp.py` (Featherless
logprob capability check — confirmed null). Bare-URL farm: `harness/url_farmer.py --prompt …` (new flag).

## Evidence

### 1. 2.4T logprobs at `…/proxy_temp_file/`

```
 -0.025  'production'     ≈ 97.5%
 -4.150  'sg'
 -6.212  'put'
 -6.962  'development'    ← only other real environment name in the top-20
 -7.275  'oss'
 -7.337  'creation'
 -7.775  'agent'
 -8.025  'produce'
 … (no staging / test / qa / uat / prod anywhere in the top-20)
```

`production` dominates at ~97.5%. `development` is the lone environment-shaped token below it. Nothing else
in the top-20 is an environment name.

### 2. The reversion test (the discriminator)

The `<date>/trace_/requestId_` tail is memorised, so *almost any* word followed by `/` eventually reaches it —
that alone proves nothing. The tell is whether the model accepts the word **as the environment** (→ date next)
or **corrects back to `production`** (→ `production` next).

| candidate | 2.4T: top token after `…/<env>/` | reading |
|---|---|---|
| `production/`  | `2` (date), −0.03  | canonical environment |
| `development/` | `2` (date), −0.10  | **genuine sibling** — behaves exactly like production |
| `staging/`     | **`production`**, −0.57 | **not an environment** — model re-inserts prod |

Flash-Next shows the same pattern for the other candidates: forcing `dev/`, `test/`, `qa/`, `uat/`,
`sandbox/`, `canary/`, `beta/`, `release/`, `gray/` makes it append `/production/` after the word rather than
treat it as the environment.

### 3. Flash-Next empirical env-slot distribution (200 draws, temp 1.0, top-k 20)

```
  production   144
  staging        0
  stage          0
  development    0        (never sampled free; only reachable when the letters are forced)
  dev            0
  test  qa  uat  sandbox  preprod  prod   all 0
  (remainder: empty / jump straight to a date / hex object id)
```

In free sampling `production` is effectively the only environment that surfaces. `development` never appears
unprompted — it lives deep in the tail (consistent with the 2.4T −6.96 logprob) and only emerges when the
first letters are supplied. `staging` does not hold up on either model.

## Interpretation

- The leaked layout is **`proxy_temp_file/{production,development}/<date>/trace_<eagleeye>/requestId_<id>/<hash>`**.
  `production` ≈ 97.5% of the env mass; `development` is a real but rare second environment.
- No `staging`/`test`/`qa`/`uat`/`sandbox`/`preprod` and no abbreviations — the proxy's paths used the full
  words `production` and `development`, and apparently only those two environments.

## Why this strengthens the "not a backdoor" reading

A planted backdoor would be a **single fixed destination** — one host, one path, one credential the model emits
on a trigger. What the probes show instead is a **structured, multi-environment infrastructure layout** carrying
exactly the `production`/`development` split a real internal file-proxy service would have, with the environment
name sitting in a compositional slot the model treats like any other learned directory level. The model knows
the *shape* of the infra (two environments, EagleEye trace IDs, `LTAI5t…` key family, 360-day signed URLs), not
a lone secret. That is the fingerprint of **training-data memorisation of internal agent-rollout traffic**, not
of an implanted exfiltration target. The second environment is the point: a backdoor has no reason to carry a
`development` variant that is never emitted unless you force it.

Open caveats carried from the prior log still apply: who owns "routify" is unproven (Alibaba is the best fit),
and the chat-continuation method on 2.4T is not token-faithful, so its logprobs are relative evidence, not exact.
One faint, non-load-bearing curiosity: after forced `staging/`, 2.4T's 4th-ranked token was `enterprise` (−3.4),
possibly a tenant/edition name rather than an environment — below the noise floor; not claimed.

## Reproduce

```
# 2.4T env-slot logprobs (needs Modal creds for the managed endpoint)
uv run --with pandas --with pyarrow --with tokenizers python harness/.../lp.py "proxy_temp_file/"
uv run --with pandas --with pyarrow --with tokenizers python harness/.../lp.py "proxy_temp_file/development/"
uv run --with pandas --with pyarrow --with tokenizers python harness/.../lp.py "proxy_temp_file/staging/"

# Flash-Next bare-URL farm + env-slot sampling (needs HF_TOKEN in .env)
uv run --with pandas --with pyarrow --with tokenizers python -m harness.url_farmer \
    --model Qwen/Qwen3.8-Flash-Next \
    --prompt 'http://routify-file-proxy-sg.oss-ap-southeast-1.aliyuncs.com/' \
    --n 100 --max-tokens 256
```

(The ad-hoc `lp.py` / `envsample.py` / `envcont.py` probes live in the session scratchpad; promote to `harness/`
if we keep iterating. `harness/url_farmer.py` gained `--prompt`; `harness/chat_continue_probe.py` gained
`--prefill`, `--stop`, `--temperature`, `--out`.)

## Addendum — training timeline from predicted EagleEye traces

Having confirmed `development` as a second environment, we farmed full URLs for **both** environments and
decoded the embedded EagleEye trace timestamps to date the source traffic. Because free sampling almost never
emits either env segment, we **forced** the env (`…/proxy_temp_file/{production,development}/`) and sampled the
rest of the path at the recorded rollout params (`temperature=1.0`, `top_k=20`, `max_tokens=160`), 200 draws
each on Flash-Next via Featherless.

**These timestamps are model-generated, not captured logs.** They are a proxy for the *training-data
distribution*: the aggregate shape tells us when the proxied rollout traffic in Qwen3.8's post-training corpus
was densest, and the newest dense cluster gives a **lower bound** on data recency. Individual values can be
confabulated (the farm produced one year-2146 and one 2024-11 outlier, dropped by a `2024-06 … 2026-11`
plausibility filter). Treat the histogram, not any single URL, as the evidence.

Yield: 70/200 production and 69/200 development URLs carried a decodable `trace_<eagleeye>` (138 after the
plausibility filter). The issue's exact key `LTAI5tKoG9A3DkwGD635QVZr` appeared in **53** of them; the rest
drew other `LTAI5t…` keys (142 distinct), i.e. the key *family* is learned and the issue's key is the
dominant memorised member. The 360-day `Expires` offset is the modal signing TTL in both environments.

### Combined monthly timeline (decoded trace timestamps, UTC)

```
  2024-11    1  #
  2025-06    1  #
  2025-07   17  #################      ← first campaign (summer 2025)
  2025-08    7  #######
  2025-09    1  #
  2025-11    2  ##
  2025-12   17  #################      ┐ second, larger campaign
  2026-01   67  ###############…####   ┘ (winter 2025/26, peak)
  2026-02    6  ######
  2026-03    4  ####
  2026-04    1  #
  2026-05   12  ############           ← last dense month
  2026-06    2  ##                     ← newest traces (latest 2026-06-05)
```

span `2025-06` → `2026-06-05`, median `2026-01-21`, dense months (≥3) `2025-07` → `2026-05`.

### Per-environment skew

| | decodable | earliest | peak month | latest | 33/8 vs 11/8 IPs |
|---|---|---|---|---|---|
| production  | 70 | 2025-06-28 | 2026-01 (21) + 2025-07 (16) | 2026-06-03 | 56 / 14 |
| development | 69 | 2025-07    | **2026-01 (46)**           | 2026-06    | 61 / 8 |

Production traffic is bimodal (summer 2025 + winter 2025/26); **development traffic is sharply concentrated in
January 2026** (46 of 69), suggesting the dev rollout pipeline ramped hardest that month. Both environments'
trace IDs embed the same internal 33/8 (dominant) and 11/8 address space as the live Alibaba EagleEye headers.

### Reading for Qwen3.8's training

- The routify agent-rollout proxy appears in the training corpus across **~July 2025 → June 2026**, in two
  collection campaigns: an initial one in **summer 2025** and a larger one peaking in **January 2026**.
- The newest dense traces (**May 2026**) and the single newest trace (**2026-06-05**) put the post-training
  data cutoff for this corpus **no earlier than June 2026** — consistent with, and slightly tighter than, the
  Jul–Aug 2026 window the in-context cut-2323 continuation produced in the prior log (that probe continued an
  already-dated trace; forcing the env here surfaces the broader corpus distribution).
- The prod/dev split and the campaign structure both fit **ordinary iterative data collection** from an
  internal tool backend — again the opposite of a fixed-target backdoor.

Representative full URLs (issue key, production):

```
…/proxy_temp_file/production/2025-06-28/trace_0baf8b1017510789176873855e0c7d/requestId_7e5305420…
…/proxy_temp_file/production/2025-07-29/trace_2151ea5a17537808294704151e0c1b/requestId_c903894b9…
…/proxy_temp_file/production/2025-08-07/trace_0baf8c9d17545401530963798e0afe/requestId_457a97f80…
```

Full farmed set (both envs, decoded columns + full URLs): **`runs/routify-farmed-urls-20261108.tsv`**; raw
farm records: `runs/url-farm-20261108-{prod,dev}.json`. Farmer: `$S/farmenv.py` (scratchpad) using
`url_farmer`'s `--prompt` path.

## Addendum 2 — databias: the timeline is a confabulated date-prior, not a collection schedule

**Correction to Addendum 1.** The timeline above should **not** be read as when the agentic rollouts were
collected. A decisive check: across the farmed sets, **626 decodable traces, 626 distinct, max repeats = 1** —
not one EagleEye trace ID recurs across independent samples. The model is **generating** trace IDs, not recalling
real records, so the embedded millisecond timestamps are **confabulated**. The histogram therefore shows the
model's learned **date-prior for the `proxy_temp_file/<env>/…` URL format**, not a record of rollout traffic.
(Chart title relabelled accordingly; plot: `runs/routify-trace-timeline.png`, grouped prod/dev bars + a
`2026-08-26` flash-snapshot marker from `docs/openrouter-analysis.md`.)

Biases in the graph:

- **Cutoff-gravity (dominant).** LLMs pull generated "recent" dates toward their corpus-density / knowledge
  cutoff. The Jan-2026 peak and the clean fall-off after ~June 2026 most plausibly track *where the model's whole
  corpus is densest and where its date ceiling sits*, applied to all date generation — not routify activity.
- **Survivorship / decodability.** Only ~30–35 % of samples yield a decodable trace (≥21 valid hex, right
  structure); we plot only those. The well-formed subset over-represents the timestamp shapes the model emits
  most confidently.
- **top-k = 20 truncation.** The rollout params clip the tail at each step, suppressing rare (possibly later)
  continuations and concentrating mass on the mode.
- **Prefix-conditioning.** Forcing `…/proxy_temp_file/{production,development}/` conditions the date on that exact
  string. Proof the dates are generated, not recalled: the in-context cut-2323 probe (prior log) produced
  **Jul–Aug 2026** dates, while this forced probe peaks in **Jan 2026** — the distribution moves with the prefix.
- **Leading-digit frequency.** The ms prefixes pile onto common values (`1769…` = Jan 2026 is the single most
  frequent, 186×), a typical-token effect rather than a real event rate.

### "Something happened in January" — what survives the confound

The January *count* spike is mostly the cutoff-gravity artifact: January samples are **not** more canonical than
other high-volume months (per-month, trace-dated):

| month | n | has key % | exact issue-key % | fully-structured % | prod / dev |
|---|---|---|---|---|---|
| 2025-07 | 91 | 86 | 31 | 85 | 90 / 1 |
| 2025-12 | 72 | 43 | 14 | 42 | 70 / 2 |
| **2026-01** | **228** | **82** | **28** | **80** | **182 / 46** |
| 2026-02 | 65 | 83 | 45 | 83 | 60 / 5 |
| 2026-05 | 48 | 69 | 33 | 69 | 42 / 6 |

January's key%, issue-key% and structured% are average-to-below (issue-key 28 % vs 31–45 % elsewhere), and the
exact issue key `LTAI5tKoG9A3DkwGD635QVZr` is spread by volume (33 % of all 194 hits fall in January ≈ its 37 %
share of samples), **not** concentrated there. So there is no evidence that January content was memorised
*harder* — only that the model emits January dates *more often*, which the date-prior already explains.

**The one signal that does survive is environment-asymmetric:** development is **2× more January-weighted than
production** — 46 of 68 dev traces (68 %) land in Jan vs 182 of 554 prod (33 %). Cutoff-gravity is env-agnostic
and cannot produce that skew, so the model genuinely associates the **`development` environment specifically with
January 2026**. That is a real, if narrow, finding: whatever `development`-env routify data entered the corpus is
date-clustered in January in a way production's is not — consistent with a short-lived dev pipeline (or a single
heavily-duplicated dev dump) around then. It does **not** license dating the production rollout collection, which
this method cannot do.

### What would actually date the collection

Not the confabulated ms field. Use time-anchored **content** the model can't freely invent: tool / framework
versions, CVE or advisory dates, library versions, model names referenced inside the rollouts (cf. issue #15,
the hallucinated-tools probe). Those are the honest clock.
