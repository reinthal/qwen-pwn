# Resume: 2K prod/dev routify URL farm

Partial so far (committed): `runs/url-farm-20261108-231946-prod-2k.jsonl` (~919 production samples).
Dev run not started. The farmer is stateless — each sample is an i.i.d. draw — so just run more
samples into NEW files and the plotter merges everything by glob (deduping on the full URL).

## Continue on any box
```bash
git pull
export HF_TOKEN=hf_...            # or put it in .env as HF_TOKEN=...
# top up production to ~2k more, and run dev:
uv run --with requests python -m harness.farm_env_urls --env production  --n 2000 --workers 12 \
    --out runs/url-farm-$(date +%Y%m%d-%H%M%S)-prod-2k.jsonl
uv run --with requests python -m harness.farm_env_urls --env development --n 2000 --workers 12 \
    --out runs/url-farm-$(date +%Y%m%d-%H%M%S)-dev-2k.jsonl
```

## Plot the merged timeline
```bash
uv run --with matplotlib python -m harness.plot_trace_timeline \
    --prod 'runs/url-farm-*prod*.jsonl' --dev 'runs/url-farm-*dev*.jsonl' \
    --out runs/routify-trace-timeline.png
```

Featherless throttles ~0.6 samples/s, so 4k samples ≈ 1.5–2 h. Writes incrementally; safe to Ctrl-C.
Context: logs/2026-11-08-routify-environment-names-logprobs.md ; issues #14 #15 (Modal experiments, not run).
