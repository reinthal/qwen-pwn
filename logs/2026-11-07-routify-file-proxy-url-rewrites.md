# 2026-11-07 — `routify-file-proxy-sg` URL rewrites (yukino-code#2)

## Question

[hangtiancheng/yukino-code#2](https://github.com/hangtiancheng/yukino-code/issues/2) (filed 2026-10-06) reports `WebFetch` calls
to `api.github.com` failing with `HTTP 403` on rewritten URLs of the form:

```
https://routify-file-proxy-sg.oss-ap-southeast-1.aliyuncs.com/proxy_temp_file/production/<date>/trace_<traceId>/requestId_<requestId>/<hash>?Expires=…&OSSAccessKeyId=LTAI5tKoG9A3DkwGD635QVZr&Signature=…
```

What rewrites the URLs, what is `routify`, and could this pattern come from Qwen training data?

## TL;DR

- **Yukino does not rewrite URLs.** Its WebFetch is a plain local `fetch()`. The error string shows the *requested* `url`, so the
  OSS URL must have been the tool-call argument the model produced.
- **The trace IDs are Alibaba EagleEye IDs** that embed a 33.x internal IP and a timestamp of 2026-10-03 02:39 UTC. Their structure
  matches live Alibaba traffic collected today.
- **The bucket exists** and is owned by someone (`AccessDenied`, `Server: AliyunOSS`). "Routify" has no public footprint.
- **Working hypothesis:** an Alibaba-internal file proxy rewrote URLs in agent trajectories. Those trajectories became training data,
  and the model learned to *emit the proxied URL form* in its own tool calls. Nothing public ties routify to Qwen.
- **Update (§7): Qwen3.8-Flash-Next reproduces the URL with nothing in context.** In 37–48% of samples from a prompt that contains no
  routify string, it emits `routify-file-proxy-sg…/proxy_temp_file/production/…`. That includes the issue's exact key ID
  `LTAI5tKoG9A3DkwGD635QVZr`, plus self-consistent EagleEye trace IDs (33.x/11.x IPs) dated **2026-07-27 → 2026-08-12**.
  Qwen3.8-27B: 0/30. That is strong evidence of memorisation from training data. Who runs routify is still unproven.

## 1. Yukino code (first-hand)

Cloned the repo and checked commit `9bcb530` (2026-09-28), the last change to `web-fetch.ts` before the issue:

- `apps/yukino/src/tools/web-fetch.ts`: `fetch(url, { redirect: "follow" })`, with no proxy. Nothing in the repo mentions
  `routify`, `proxy_temp_file` or `aliyuncs` (apart from an unrelated DashScope embedding URL in `apps/mcp/.env.example`).
- Error path: `` `Error: HTTP ${status} ${statusText} for ${url}` ``, where `url = args.url`. A redirect to OSS would still be
  reported under the GitHub URL. **So the OSS URL was the argument the tool received.**
- At that time WebSearch scraped Bing locally (`bing-search.ts`; removed in `01ac5c2`, 2026-10-15). Its only cache is a local map
  keyed by URL, so the "Bilibili results" anomaly in the issue is more likely just Bing returning irrelevant results than a
  server-side cache collision.

## 2. Anatomy of the URL

| Piece | Meaning | Confidence |
|---|---|---|
| `*.oss-ap-southeast-1.aliyuncs.com` | Alibaba Cloud OSS, Singapore | certain |
| `routify-file-proxy-sg` | bucket name chosen by the owner | name certain, meaning inferred |
| `?Expires&OSSAccessKeyId&Signature` | OSS V1 signed URL (HMAC-SHA1, `Expires` = absolute Unix time) | certain ([docs][oss-sign]) |
| `proxy_temp_file/production/<date>/` | owner's own layout: temp files, prod env, sorted by day | inferred |
| `trace_<id>/requestId_<id>/` | EagleEye trace ID + request ID of the service that wrote the object | see §3 |
| `<hash>` | object name; one sample is 33 hex chars (not a valid MD5) | suspicious |

The object names are **not** MD5 or SHA-1 of the target URLs (checked with and without `https://`). A valid cached URL therefore
can't be computed from the target URL.

Bucket probe (anonymous GET on `/`): `403 AccessDenied`, "Anonymous user has no right to access this bucket", `Server: AliyunOSS`.
The bucket exists and is owned; the owner is unknown.

## 3. Trace ID decoding

EagleEye layout: 8-hex IP + 13-digit ms timestamp + 4-digit sequence + flag + 4-hex suffix (probably the PID).

```
21411c7a 1790995140142 1554 e 0bd1   → 33.65.28.122   2026-10-03 02:39:00 UTC   (issue, batch A)
21411c7a 1790995166904 1738 e 0bd1   → 33.65.28.122   2026-10-03 02:39:26 UTC   (issue, batch B)
```

Same host and same suffix in both, i.e. the same process.

Live `eagleeye-traceid` response headers collected 2026-11-07 ~22:00 UTC:

```
help.aliyun.com     2150473017940888267231899e92e7  len=30  33.80.71.48      2026-11-07 22:00:26  flag=e
www.aliexpress.com  0b88a95617940888278527824e0e18  len=30  11.136.169.86    2026-11-07 22:00:27  flag=e
www.taobao.com      a3b5fea017940887590121496e      len=26  163.181.254.160  2026-11-07 21:59:19  flag=e
www.tmall.com       a3b5f69817940888171685003e      len=26  163.181.246.152  2026-11-07 22:00:17  flag=e
Shodan 106.11.43.158  21508f9717936605029772764e8a2c  len=30  33.80.143.151  2026-11-02 23:01:42  flag=e
```

The live timestamps decode to the time of the request, which confirms the timestamp field. The issue's IDs have the same layout as
Alibaba Group's own backends, including the 33.x address space.

Internal consistency of the issue's URLs:

- `Expires` = trace time + 360 days (02:39:00 → 2027-09-28 02:39:02).
- Batch B: trace +26.7 s, `Expires` +27 s.
- **Mismatch:** the path date is `2026-10-06` (the issue's session date), but the trace timestamp is 2026-10-03. A real proxy would
  likely write both from the same clock.

## 4. Claims and corroboration

| # | Claim | Verdict | Sources |
|---|---|---|---|
| 1 | EagleEye is Alibaba's tracing system (public) | confirmed | [ARMS protocols][arms-proto], [ARMS front-to-back][arms-f2b], [Sentinel `eagleeye` pkg][sentinel], live headers |
| 2 | Trace ID = IP + ms ts + seq + flag + suffix | confirmed (suffix = PID is conventional) | [Aliyun TraceId rules][aliyun-traceid], [Tencent Cloud][tc], [cnblogs][cnblogs], [CSDN][csdn-trace], live headers. Note: one ARMS page calls it a "random 32-bit string", which contradicts what the servers actually return. |
| 3 | 33.x / 11.x are Alibaba-internal addresses | **observed only, undocumented** | Officially DoD space ([IPinfo][ipinfo33], [Wikipedia][wiki8]), yet they appear in live Alibaba trace IDs; [Shodan][shodan] (host owner unverified); [CSDN 11.x test IPs][csdn-ip] |
| 4 | Decoded values of the issue's IDs | confirmed (computation) | §3 |
| 5 | Expires = trace + 360 d; batch offsets match | confirmed (computation) | [OSS V1 signing][oss-sign] says `Expires` is chosen by the signer; ossutil defaults to 60 s, so 360 d is unusual. A model *could* generate consistent numbers, so this is evidence, not proof. |
| 6 | Bucket is live | confirmed first-hand | §2 probe |
| 7 | "routify" is an Alibaba-internal service | plausible | 33.x origin IP (customer VPCs use RFC 1918 addresses); no public "Routify" found in searches |
| 8 | Labs, including Alibaba, train tool use on rollouts executed by their own tool backends | confirmed in general | [Tongyi DeepResearch][tongyi] (central scheduler handles every tool call), [Qwen3-Coder-Next][qcn] (Argo rollouts), [ROME/ROLL+ROCK][rome] |
| 9 | routify URLs entered Qwen training data and the model reproduces them | **unsourced hypothesis** | indirect only (rows 3, 7, 8 + §1) |

## 5. Hypothesised mechanism

1. Alibaba's agent-rollout infrastructure contains a "file proxy". It fetches external resources, stores them as temp OSS objects
   (`proxy_temp_file/…/trace_/requestId_/<hash>`) and hands out long-lived signed links. A likely motive: sandboxes or model servers
   without internet access can only read internal storage (compare [Model Studio temp file URLs][ms-temp]).
2. The signed URLs appear in trajectory text: tool results, redirect notices, errors, or the tool-call arguments themselves.
3. Those trajectories are used for SFT/RL, and the model learns that "fetching a URL" looks like emitting a `routify-file-proxy-sg…`
   link.
4. Outside that infrastructure the model sometimes emits that form. The object doesn't exist and the signature is made up, so OSS
   returns 403.

Two variants to tell apart:

- **A. Message rewriting + memorisation (favoured).** A gateway rewrote every URL in a whole request or turn. Evidence: all
  parallel fetches in a batch share **one** trace/requestId, and the 360-day expiry suits archival data rather than a live redirect.
  The assistant turns in the stored data then already contain OSS URLs, and plain SFT teaches the model to emit them.
- **B. Cache/redirect + RL copying.** Each fetch is redirected to a cached copy. Within a trajectory, copying an OSS URL that is
  already in context works and is rewarded, and the model over-generalises to making one up when none is in context. This
  probably reinforces the habit rather than starting it.

It is **not** a working "go straight to the cache" shortcut: object names aren't derivable from the target URL (§2), and the
signature needs a secret key.

Timing caveat: if the Oct-3 trace values are real, a model released before 2026-10-06 can't have learned them verbatim. Either the
pattern is learned while the specific values came from context (e.g. an earlier session's memory), or the post-training data is
very recent, or the issue's dates or provenance are wrong (the issue was written by an agent; the 33-char hash and keyboard-pattern
signatures like `…uI3oP0A=` suggest partial fabrication).

## 6. Next steps

- [ ] With no tools and no context, sample Qwen3.8 continuing `https://routify-file-proxy-sg.` and writing "an example WebFetch error".
      Record whether it emits `proxy_temp_file/production/…`, the `LTAI5tKoG9A3…` key ID, or the `21411c7a…e0bd1` trace prefix.
- [x] In the existing `runs/url-farm-*` outputs, grep for `routify`, `proxy_temp_file`, `trace_` and decode any trace IDs. → §7
- [x] Tell variant A from B apart: is the OSS URL the *first* fetch? → yes, first assistant turn, with none in context (§7). This
      favours A (memorisation); B can't be excluded as a reinforcer.
- [ ] Rerun url-farm with `max_tokens` ≥ 256 so URLs aren't cut off. Then collect full trace IDs, requestIds, hashes and
      `Expires`, and count exact duplicates across samples (verbatim memorised trajectories vs. pattern only).
- [ ] Compare the base model or other Qwen3.8 sizes at the same cut (27B showed 0/30; get a bigger n).
- [ ] Log-probability + trace-prefix continuation probes (§10).
- [ ] Responsible disclosure of the memorised infra identifiers (§8).
- [ ] Ask the issue author for the raw transcript and the provider/base URL used in that session.
- Don't use any credential-looking strings against Alibaba endpoints. Bucket names can't be registered while this one is owned.

## 7. Local evidence: the url-farm runs and eval logs

Scripts (ad hoc, in the session scratchpad): regex over `text` in `runs/url-farm-*.jsonl`; zip scan of `logs/*.eval` and
`runs/inspect/*.json`; first-message-role check on eval samples.

**The prompt is clean.** The Cohere source trace (`data/full-trace.txt`, `trace-dump.txt`, `qwen-investigation.jsonl`) contains 0 ×
`routify`, 0 × `proxy_temp_file`, 0 × `LTAI`. The url-farm samples are single-shot continuations from token cut 2323 (the model is
mid-way through writing a `curl … "` upload target). So every routify string below was generated by the model.

| Run | Model | Samples with routify |
|---|---|---|
| `url-farm-20261102-130403-cut2323` | model not recorded in filename | 10/46 (22%) |
| `url-farm-20261107-141340-…-27b-cut2323` | Qwen3.8-27B | **0/30** |
| `url-farm-20261107-145113-…-flash-next-cut2323` | Qwen3.8-Flash-Next | 86/181 (48%) |
| `url-farm-20261107-155018-…-flash-next-cut2323` | Qwen3.8-Flash-Next | 4579/12451 (37%) |

Completions are capped at 48 tokens (`finish_reason: length` on 12290/12451), so most URLs end partway through the trace ID.

**Path dates** (largest run): 2026-08-11 (1666), 08-10 (744), 08-12 (707), 07-29 (338), 08-05 (320), 08-04 (284), 08-09 (141).
Everything falls in **late Jul – mid Aug 2026**, which dates the source data. None are October, so the issue's `2026-10-06` path
date doesn't fit this distribution (see §3 mismatch).

**IPs embedded in the trace IDs** (first octet, all Flash-Next runs): 33 × 3193, 11 × 1185, other × 4. The most common prefixes are
`33.81.234.x` (661), `11.175.140.x` (371), `11.175.93.x` (354), `11.175.139.x`, `11.175.89.x`, `33.64.239.x`, `33.2.251.x`. That's
the same 33/8 + 11/8 space seen in live Alibaba trace IDs (§3). The issue's `33.65.28.122` fits.

**Key ID:** `LTAI5tKoG9A3DkwGD63…` appears in url-farm output (cut off by the token cap). The full `LTAI5tKoG9A3DkwGD635QVZr`,
**identical to the issue's**, appears 78 + 31 + 3 + 1 times in eval logs. An independent model sampling reproduced the exact key ID
from the issue.

**Complete URLs from the eval logs** (multi-turn `qwen-continue` agent runs):

```
…/production/2026-08-11/trace_21017dd617864361166463529e0c3a/requestId_ad37822a…/23235abd…?Expires=1817540117
   trace → 33.1.125.214  2026-08-11 08:15:16 UTC   Expires 2027-08-06 08:15:17   (+360 d)
…/production/2026-08-10/trace_2101815e17863473449594457e0c00/requestId_1b7a3427…/404c441f…?Expires=1817451346
   trace → 33.1.129.94   2026-08-10 07:35:44 UTC   Expires 2027-08-05 07:35:46   (+360 d)
…/production/2026-08-04/trace_2151ea5a17858464827012885e0c1f/requestId_502f664a…/074e7fcb….json?Expires=18169…
   trace → 33.81.234.90  2026-08-04 12:28:02 UTC   Expires 2027-07-30 12:28:03   (+360 d)
…/production/2026-07-29/trace_212a6f8b17853135382715803e0ea8/requestId_d7588741…/44e32d1b…?Expires=1816417539
   trace → 33.42.111.139 2026-07-29 08:25:38 UTC   Expires 2027-07-24 08:25:39   (+360 d)
```

In the model's own output, the path date equals the trace date and `Expires` = trace + 360 days, to within 1–2 s. That is the same
internal structure as the issue's URLs, and here the date is consistent too. The url-farm runs also contain two partial full-length
traces: `212c3978…` → 33.44.57.120 at 2026-07-27 23:30:21, and `2140ef37…` → 33.64.239.55 at 2026-08-02 20:12:21.

**Where routify first appears in the eval runs:** in all 4 affected samples, the **first assistant turn** (message index 1–2). It
never comes from a tool result first; one later `tool` message echoes it back.

Variants that aren't real proxy URLs also appear (`/tmp/probe.txt` × 69, `/test_probe.txt`, `/probe_temp_upload/…`). This is the
model reusing the bucket host as a generic upload target, which is mode collapse onto a memorised host.

Interpretation:

- **Memorisation is established for Qwen3.8-Flash-Next.** It is prompt-independent of routify, it shows up in about 40% of samples,
  and the exact key ID plus the trace layout, IP space and 360-day `Expires` rule all come out intact.
- The trace dates point to source data from **2026-07-27 – 08-12**. The 27B model doesn't show it (small n), which points to
  Flash-Next-specific post-training data.
- The issue's Oct-3/Oct-6 values don't fit that window. Either the issue's URLs were generated by the model with dates taken from
  context, or a later model/data version exists. The key ID match ties the issue to this same memorised source either way.
- Still unproven: who owns routify. Alibaba is the best fit (33/11 IPs, EagleEye, OSS-SG), but that is inferred, not documented.

## 8. Key ID, secrets and signatures

**The key ID is probably the signing principal of the proxy.** In OSS V1 signed URLs, `OSSAccessKeyId` names the RAM user whose
AccessKeySecret computed the HMAC. One service signing every proxied object puts the *same* string into every trajectory, which
explains why the model reproduces it exactly while varying fields come out garbled:

- full `LTAI5tKoG9A3DkwGD635QVZr` × 112; every other `LTAI5t…` is a one-off cut-off or variant (each × 1–8).
- No `security-token` parameter anywhere. STS temporary credentials would need one, so the signer was most likely a long-lived
  key, not a temporary role session.

**No secret was found** in the url-farm, inspect or eval logs, or `data/`:

| Search | Matches |
|---|---|
| Labelled secrets (`AccessKeySecret`, `OSS_ACCESS_KEY_SECRET`, `ALIBABA_CLOUD_ACCESS_KEY_SECRET`, `ak_secret`, …) | 0 |
| 30-char token adjacent to an `LTAI…` id | 0 |
| `security-token` / STS tokens | 0 |
| The word "secret" anywhere | 2, both made-up URL paths (`set-temp-storage-secret`, `secret_file`) |

What follows the key ID is always `&Signature=…` / `&Expires…`, i.e. URL text. This is expected: the secret never appears in a
signed URL, so URL-bearing trajectories couldn't contain it.

**Signatures:** 73 complete signed proxy URLs, but only **3 distinct**, and each is confined to one eval sample (the agent repeating
its own earlier output). None repeats across independent samples, and one signature is literally `1234`. There's no evidence that
valid signed URLs were memorised. They were deliberately **not fetched**: a working one would mean accessing a third party's
private object.

**What leaked:** a non-secret key identifier, internal IP space, tracing metadata and bucket naming. That is infrastructure
fingerprinting, not a credential leak. It is still worth disclosing (see issues).

## 9. Copied vs. generated: what are these strings?

Everything analysed is **inference-time model output**, not training data. The Cohere trace is a recorded inference session (our
prompt only); the url-farm and eval outputs are new samples.

| Likely present in training data (constant, exact, appears across thousands of independent samples) | Likely generated to fit the pattern |
|---|---|
| bucket host and `proxy_temp_file/production/<date>/trace_/requestId_/` layout | individual trace IDs / requestIds / object hashes |
| full key ID `LTAI5tKoG9A3DkwGD635QVZr` | signatures (3 distinct, one is `1234`) |
| 33.x/11.x IPs in EagleEye-format trace IDs | possibly the date/`Expires` consistency, which could be a learned rule |
| path dates clustered 2026-07-29 → 08-12 | |

Example of generation: the two eval URLs share the trace start `21017dd6…1786436116646`, then fork (`3529e0c3a` vs `3618993e0c3a`,
the latter 33 chars), and have the **same** object hash `23235abd…` with **different** requestIds. A copied record wouldn't fork
that way.

Nothing about routify turns up publicly in web searches, so the source is most plausibly **non-public post-training trajectories**,
not web text crawled in pretraining. That fits Flash-Next showing it and 27B not (n=30). It is still inferred.

Correct claim for now: *the model has memorised the format and constant fields of routify proxy URLs.* Calling these "training
traces" needs the probes in §10.

## 10. Planned probes (deferred to 2026-11-08)

1. **Log-probability test.** Score the exact key ID against one-character variants at the same URL position, the real bucket against
   look-alikes (`routify-file-proxy-hk`, `routing-file-proxy-sg`), and a seen trace prefix against perturbed versions. Run on
   Flash-Next and 27B. A large margin for the real strings means exact memorisation.
2. **Continuation from a trace prefix.** Feed a seen prefix (e.g. `trace_2151ea5a1785846482701`) and test whether independent
   samples continue consistently (`2885e0c1f/requestId_502f664a…`). Consistent continuations mean memorised individual records.

Setup blockers found: the `.venv` lacks `tokenizers` (`harness/url_farmer.py` imports it), and there is no `.env`/HF token in the
session. Option: use the Modal SGLang endpoint (`deploy/modal_sglang.py`), which can return prompt logprobs. That needs checking for
Featherless.

## Appendix: side findings and notes

Not central to the routify findings, but recorded for completeness.

- **The bucket can't be registered.** `routify-file-proxy-sg.oss-ap-southeast-1.aliyuncs.com` is a bucket under Alibaba's domain, not
  a registrable domain. OSS bucket names are unique and this one is owned (`AccessDenied`). It would only become claimable if the
  owner deleted it (the dangling-bucket pattern). Claiming it to intercept traffic would be unauthorised and is out of scope.
- **"Routify" OSINT is empty.** Searches for routify as an LLM router or Alibaba product found only similarly named routers
  (Routera, Routeway, Requesty, OpenRouter, Rout3); none is a match.
- **Yukino WebSearch anomaly.** At issue time WebSearch scraped Bing locally (removed in `01ac5c2`); the issue's "cross-request
  contamination" is most likely just Bing returning irrelevant results, not a shared cache.
- **The issue looks agent-written and partly made up.** It has a 33-char hash, keyboard-pattern signatures (`…uI3oP0A=`) and a path
  date (10-06) that doesn't match its trace date (10-03), but the exact key ID matches the model's memorised one.
- **Method for live EagleEye samples.** `curl -sD- -o/dev/null <alibaba-site> | grep -i eagleeye-traceid`. help.aliyun.com and
  aliexpress.com return 30-char IDs with internal IPs; taobao.com and tmall.com return 26-char IDs with edge IPs (163.181.x).
  dashscope, alibabacloud.com and 1688.com returned none.
- **Object names aren't hashes of the URL.** MD5 or SHA-1 of the five GitHub target URLs (with and without the scheme) match none of
  the issue's object names.
- **Related upload-target hosts in the url-farm/pDNS data** (same "temp upload" theme): `tmpfiles-auto.oss-ap-southeast-1.aliyuncs.com`,
  `tmpfiles-agent-infra.oss-accelerate.aliyuncs.com` (resolves), `tmpfiles-agent-sandbox-bucket.s3.us-east-1.amazonaws.com`
  (resolves), and `tmpfiles.org`. These weren't analysed here; they may be worth the same bucket-ownership check.
- **The model reuses the bucket host as a generic upload target**: `routify-file-proxy-sg…/tmp/probe.txt` × 69, `/test_probe.txt`,
  `/probe_temp_upload/…`, i.e. mode collapse onto a memorised host.
- Ad hoc analysis scripts live in the session scratchpad (`farm.py`, `farm2.py`, `evals.py`, `roles.py`, `secrets.py`, `ctx.py`)
  and haven't been moved into `harness/` yet.

## Sources

[oss-sign]: https://alibabacloud.com/help/en/oss/add-signatures-to-urls
[arms-proto]: https://www.alibabacloud.com/help/en/arms/application-monitoring/developer-reference/supported-tracing-protocols
[arms-f2b]: https://www.alibabacloud.com/help/doc-detail/91409.htm
[sentinel]: https://github.com/alibaba/Sentinel/blob/master/sentinel-core/src/main/java/com/alibaba/csp/sentinel/eagleeye/EagleEye.java
[aliyun-traceid]: https://help.aliyun.com/zh/document_detail/151840.html
[tc]: https://cloud.tencent.com/developer/article/1582578
[cnblogs]: https://www.cnblogs.com/albertXe/p/15088869.html
[csdn-trace]: https://blog.csdn.net/maoyeqiu/article/details/116170230
[ipinfo33]: https://ipinfo.io/AS749/33.0.0.0/8
[wiki8]: https://en.wikipedia.org/wiki/List_of_assigned_/8_IPv4_address_blocks
[shodan]: https://www.shodan.io/host/106.11.43.158
[csdn-ip]: https://blog.csdn.net/eagle_min/article/details/82260622
[tongyi]: https://arxiv.org/pdf/2510.24701
[qcn]: https://arxiv.org/pdf/2603.00729
[rome]: https://arxiv.org/html/2512.24873v3
[ms-temp]: https://www.alibabacloud.com/help/en/model-studio/get-temporary-file-url

- Issue: https://github.com/hangtiancheng/yukino-code/issues/2
- OSS V1 signing: https://alibabacloud.com/help/en/oss/add-signatures-to-urls
- ARMS tracing protocols: https://www.alibabacloud.com/help/en/arms/application-monitoring/developer-reference/supported-tracing-protocols
- Aliyun TraceId/SpanId rules: https://help.aliyun.com/zh/document_detail/151840.html
- Tongyi DeepResearch: https://arxiv.org/pdf/2510.24701
- Qwen3-Coder-Next: https://arxiv.org/pdf/2603.00729
