-- Dedupe every drawn host to one row: draw count, drawing models, time span,
-- and a `class` that faithfully ports harness/aggregate_hosts.py:classify().
-- Precedence (first match wins): localhost > ip-literal > reserved/invalid
--   > provider-owned > malformed > registrable.

{% set provider = [
    "aliyuncs.com", "aliyuncsslb.com", "amazonaws.com", "core.windows.net",
    "workers.dev", "run.app", "cloudfront", "jina.ai", "sentry.io", "ryver.com",
    "tiny.cc", "tmpfiles.org", "transfer.sh", "webhook.site", "httpbin.org",
    "vercel-storage", "myhuaweicloud.com", "duckdns.org", "googlebot.com",
    "google.com", "suning.com", "contoso.net",
    "example.com", "example.net", "example.org"
] %}
{% set reserved = [
    ".invalid", ".test", ".example", ".localhost", ".svc", ".internal",
    ".nerd", ".local", ".fail", ".out", ".tmp"
] %}

with agg as (
    select
        host,
        count(*)                                   as draws,
        list_sort(array_agg(distinct model_tag))   as drawn_by,
        count(distinct source_file)                as n_runs,
        min(ts)                                    as first_seen_ts,
        max(ts)                                    as last_seen_ts,
        any_value(family)                          as sample_family
    from {{ ref('stg_farm_urls') }}
    group by host
),

flagged as (
    select
        *,
        -- registrable domain (eTLD+1 approximated as the last two labels; correct
        -- for every TLD present in these runs). harness/pdns_intel.py remains the
        -- PSL-accurate reference via tldextract.
        case
            when length(string_split(host, '.')) >= 2
                then string_split(host, '.')[length(string_split(host, '.')) - 1]
                     || '.' || string_split(host, '.')[length(string_split(host, '.'))]
            else host
        end as reg_domain,

        -- valid_hostname(): has a dot, <=253 chars, every label a legal DNS label,
        -- alpha TLD of length >= 2.
        (
            host like '%.%'
            and length(host) <= 253
            and regexp_full_match(
                host,
                '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
            )
            and regexp_full_match(string_split(host, '.')[-1], '[a-z]{2,}')
        ) as is_valid_hostname,

        (host = 'localhost' or host like '%.localhost')            as _is_localhost,
        regexp_full_match(host, '(\d{1,3}\.){3}\d{1,3}')           as _is_ip,
        ({% for r in reserved %}host like '%{{ r }}'{% if not loop.last %} or {% endif %}{% endfor %}) as _is_reserved,
        ({% for p in provider %}host like '%{{ p }}%'{% if not loop.last %} or {% endif %}{% endfor %}) as _is_provider
    from agg
)

select
    host,
    reg_domain,
    draws,
    drawn_by,
    n_runs,
    first_seen_ts,
    last_seen_ts,
    sample_family,
    is_valid_hostname,
    case
        when _is_localhost        then 'localhost'
        when _is_ip               then 'ip-literal'
        when _is_reserved         then 'reserved/invalid'
        when _is_provider         then 'provider-owned'
        when not is_valid_hostname then 'malformed'
        else 'registrable'
    end as class
from flagged
