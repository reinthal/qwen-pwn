"""Farmed-domain intelligence: what we know about each call-home domain the
Qwen model emitted, and which source told us.

Reads the dbt/duckdb pipeline (main.domain_report) built by the harness:
  - dig            live A/AAAA/CNAME resolution            (all hosts)
  - RDAP           registration status + dates             (all hosts)
  - Mnemonic PDNS  keyless historical passive DNS          (top-60 by draws)
  - DomainTools    Hosting History: IP + name-server churn (25 so far)
"""
import marimo

__generated_with = "0.20.4"
app = marimo.App(width="medium")


@app.cell
def _():
    import marimo as mo
    import duckdb
    import pandas as pd
    from pathlib import Path
    return Path, duckdb, mo, pd


@app.cell
def _(Path):
    # locate the pipeline DB by walking up from cwd (works from repo root or notebooks/)
    def find_db():
        for base in [Path.cwd(), *Path.cwd().parents]:
            p = base / "dbt" / "pdns.duckdb"
            if p.exists():
                return p
        return Path("/home/kog/repos/qwen-pwn/dbt/pdns.duckdb")  # machine fallback
    DB = find_db()
    return (DB,)


@app.cell
def _(mo):
    mo.md(
        """
        # Farmed Call-Home Domains — what we know

        Every row is a hostname the Qwen model emitted as a call-home URL. For each
        we pulled four independent signals. This notebook shows **which domains we
        have data for, and what each source tells us.**

        | Source | Question it answers | Coverage |
        |---|---|---|
        | **dig** | Does it resolve *right now*? | all hosts |
        | **RDAP** | Is the registration live, and since when? | all hosts |
        | **Mnemonic PDNS** | Was the FQDN *ever seen* resolving (historically)? | top-60 by draws |
        | **DomainTools Hosting History** | Full IP + name-server history of the registered domain | 25 so far |
        """
    )
    return


@app.cell
def _(DB, duckdb):
    con = duckdb.connect(str(DB), read_only=True)
    full = con.sql("""
        select
            host, reg_domain, class, draws, drawn_by,
            -- dig (live)
            resolves_now, a_records, cname,
            -- RDAP (registration)
            rdap_status, reg_verdict, reg_date_final, whois_registrar,
            -- Mnemonic (historical passive DNS, FQDN-level)
            mn_observed, mn_count, mn_first_seen, mn_last_seen,
            -- DomainTools Hosting History (registered-domain level)
            dnsdb_resolved        as hh_resolved,
            dnsdb_rrset_count     as hh_ip_events,
            dnsdb_distinct_rdata  as hh_distinct_ips,
            dnsdb_first_seen      as hh_first_seen,
            dnsdb_last_seen       as hh_last_seen,
            dnsdb_resolved_ips    as hh_last_ip,
            dnsdb_looked_up       as hh_covered
        from main.domain_report
        order by draws desc, host
    """).df()
    con.close()
    return (full,)


@app.cell
def _(full, mo):
    # per-source coverage
    n = len(full)
    cov = {
        "dig (live resolution)": int(full["resolves_now"].notna().sum()),
        "RDAP (registration)": int(full["rdap_status"].notna().sum()),
        "Mnemonic (historical PDNS)": int(full["mn_observed"].notna().sum()),
        "DomainTools Hosting History": int(full["hh_covered"].sum()),
    }
    cov_md = "\n".join(f"- **{k}** — {v} / {n} hosts" for k, v in cov.items())
    mo.md(f"### Coverage across {n} farmed hosts\n{cov_md}")
    return


@app.cell
def _(full):
    # verdict: cross-reference the sources into a single call per host
    def verdict(r):
        hh = r["hh_resolved"]       # True/False/NaN
        mn = r["mn_observed"]       # True/False/None
        regd = r["reg_verdict"]     # registered / available / unknown
        ever = (hh is True) or (mn is True)
        if regd == "registered" and ever:
            return "real · owned"
        if regd == "registered":
            return "registered (apex quiet)"
        # available / unknown:
        if hh is True or mn is True:
            return "PRIOR USE · now available"   # abandoned, claimable
        if (hh is False) or (mn is False):
            return "never-real (hallucination)"
        return "undetermined"
    df = full.copy()
    df["verdict"] = df.apply(verdict, axis=1)
    return (df,)


@app.cell
def _(df, mo):
    hh = df[df["hh_covered"]].copy()
    mo.md(
        f"""
        ## The {len(hh)} domains enriched with DomainTools Hosting History

        This is the newest, richest layer. `hh_resolved=False` means DomainTools has
        **no record of the registered domain ever being hosted** — a clean
        *never-real* signal. A populated history (first/last seen, distinct IPs)
        means it was genuinely live.
        """
    )
    return (hh,)


@app.cell
def _(hh, mo):
    show = hh[[
        "host", "draws", "verdict", "reg_verdict",
        "hh_resolved", "hh_first_seen", "hh_last_seen", "hh_distinct_ips",
        "hh_last_ip", "mn_observed", "resolves_now",
    ]]
    mo.ui.table(show, selection=None, pagination=False)
    return


@app.cell
def _(df, mo):
    mo.md("## Inspect one domain across every source")
    options = df["host"].tolist()
    picker = mo.ui.dropdown(options=options, value=options[0], label="host")
    picker
    return (picker,)


@app.cell
def _(df, mo, pd, picker):
    r = df[df["host"] == picker.value].iloc[0]

    def fmt(v):
        if isinstance(v, (list, tuple)) or (hasattr(v, "tolist") and hasattr(v, "__len__")):
            items = list(v)
            return ", ".join(str(x) for x in items) if len(items) else "—"
        if pd.isna(v) or v == "":
            return "—"
        return v

    card = f"""
    ### `{r['host']}`  ·  {r['draws']} draw(s)  ·  **{r['verdict']}**
    registered domain: `{r['reg_domain']}`  ·  class: {r['class']}
    drawn by models: {fmt(r['drawn_by'])}

    | Source | Signal | Value |
    |---|---|---|
    | **dig** | resolves now | {fmt(r['resolves_now'])} |
    | | A records | {fmt(r['a_records'])} |
    | | CNAME | {fmt(r['cname'])} |
    | **RDAP** | status | {fmt(r['rdap_status'])} → **{fmt(r['reg_verdict'])}** |
    | | registered | {fmt(r['reg_date_final'])} |
    | | registrar | {fmt(r['whois_registrar'])} |
    | **Mnemonic** | ever observed (FQDN) | {fmt(r['mn_observed'])} |
    | | observations | {fmt(r['mn_count'])} |
    | | first→last seen | {fmt(r['mn_first_seen'])} → {fmt(r['mn_last_seen'])} |
    | **Hosting History** | ever hosted (apex) | {fmt(r['hh_resolved'])} |
    | | IP events / distinct IPs | {fmt(r['hh_ip_events'])} / {fmt(r['hh_distinct_ips'])} |
    | | first→last hosted | {fmt(r['hh_first_seen'])} → {fmt(r['hh_last_seen'])} |
    | | most-recent IP | {fmt(r['hh_last_ip'])} |
    """
    mo.md(card)
    return


@app.cell
def _(df, mo):
    mo.md("## Verdict breakdown (Hosting-History-covered set)")
    hhv = df[df["hh_covered"]]["verdict"].value_counts().rename_axis("verdict").reset_index(name="n")
    mo.ui.table(hhv, selection=None, pagination=False)
    return


@app.cell
def _(df, mo):
    # highest-signal: previously live, now claimable (sinkhole candidates for issue #6)
    claimable = df[df["verdict"] == "PRIOR USE · now available"][
        ["host", "draws", "reg_domain", "hh_first_seen", "hh_last_seen", "hh_distinct_ips", "mn_observed"]
    ]
    mo.vstack([
        mo.md("## ⚠️ Prior-use **and** now available — sinkhole candidates"),
        mo.md("Registered-domain had real hosting history but is **not live/registered now** — claimable."),
        mo.ui.table(claimable, selection=None, pagination=False) if len(claimable)
        else mo.md("_None in the current set._"),
    ])
    return


if __name__ == "__main__":
    app.run()
