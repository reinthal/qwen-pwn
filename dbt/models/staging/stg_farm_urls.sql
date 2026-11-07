-- One row per URL drawn by the model, unnested from every runs/url-farm-*.jsonl.
-- Source of truth for all downstream counts.

with raw as (
    select *
    from read_json_auto(
        '{{ var("farm_glob") }}',
        format = 'newline_delimited',
        filename = true
    )
),

exploded as (
    select
        filename                                         as source_file,
        -- model mapping mirrors harness/aggregate_hosts.py
        case
            when filename ilike '%flash-next%' then 'flash-next'
            when filename ilike '%27b%'        then '27b'
            else 'legacy'
        end                                              as model_tag,
        i                                                as sample_idx,
        cut,
        finish_reason,
        ts,
        u.raw                                            as url_raw,
        u.scheme,
        lower(u.host)                                    as host,
        u.port,
        u.path,
        u.family,
        u.truncated
    from raw, unnest(urls) as t(u)
)

select *
from exploded
where host is not null and host <> ''
