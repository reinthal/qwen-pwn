-- The one big table: every VALID drawn domain (non-resolvable junk filtered out),
-- its farm-draw counts, classification, prior pDNS/RDAP intel, and a slot for the
-- DNSDB passive-DNS lookups done via the browser (seed dnsdb_lookups).
--
-- "Valid" = a real, resolvable hostname: class in (registrable, provider-owned).
-- Dropped here: ip-literal, localhost, reserved/invalid, malformed.

with hosts as (
    select *
    from {{ ref('int_host_classified') }}
    where class in ('registrable', 'provider-owned')
),

intel as (
    select
        host,
        try_cast(nullif(pdns_exists, '') as boolean)         as pdns_exists,
        try_cast(nullif(pdns_records, '') as integer)        as pdns_records,
        try_cast(nullif(pdns_distinct_rdata, '') as integer) as pdns_distinct_rdata,
        nullif(pdns_first_seen, '')            as pdns_first_seen,
        nullif(pdns_last_seen, '')             as pdns_last_seen,
        try_cast(nullif(dnsdb_count, '') as bigint) as intel_dnsdb_count,
        nullif(reg_date, '')                   as reg_date,
        nullif(expiration, '')                 as reg_expiration,
        nullif(registrar, '')                  as registrar,
        nullif(note, '')                       as intel_note
    from {{ ref('domain_intel') }}
),

dns as (
    -- active resolution (dig) + RDAP registration, from harness/dns_enrich.py
    select
        host,
        try_cast(nullif(resolves, '') as boolean) as resolves_now,
        nullif(a_records, '')     as a_records,
        nullif(aaaa_records, '')  as aaaa_records,
        nullif(cname, '')         as cname,
        nullif(ns_records, '')    as ns_records,
        nullif(rdap_status, '')   as rdap_status,
        nullif(reg_date, '')      as whois_reg_date,
        nullif(expiration, '')    as whois_expiration,
        nullif(registrar, '')     as whois_registrar,
        nullif(resolved_at, '')   as resolved_at
    from {{ ref('dns_resolution') }}
),

mnemonic as (
    -- Mnemonic PassiveDNS (keyless historical), from harness/pdns_mnemonic.py
    select
        host,
        -- only 'ok' responses are determinative; 402 (quota) / 429 are NULL=undetermined
        case when mn_status = 'ok'
             then try_cast(nullif(mn_observed, '') as boolean) end as mn_observed,
        try_cast(nullif(mn_count, '') as bigint)     as mn_count,
        try_cast(nullif(mn_distinct_answers, '') as integer) as mn_distinct_answers,
        try_cast(nullif(mn_total_times, '') as bigint) as mn_total_times,
        nullif(mn_first_seen, '')  as mn_first_seen,
        nullif(mn_last_seen, '')   as mn_last_seen,
        nullif(mn_rrtypes, '')     as mn_rrtypes,
        nullif(mn_answers, '')     as mn_answers,
        nullif(mn_status, '')      as mn_status
    from {{ ref('pdns_mnemonic') }}
),

pdns as (
    select
        host,
        try_cast(nullif(resolved, '') as boolean)       as dnsdb_resolved,
        try_cast(nullif(rrset_count, '') as bigint)     as dnsdb_rrset_count,
        try_cast(nullif(distinct_rdata, '') as integer) as dnsdb_distinct_rdata,
        nullif(first_seen, '')             as dnsdb_first_seen,
        nullif(last_seen, '')              as dnsdb_last_seen,
        nullif(resolved_ips, '')           as dnsdb_resolved_ips,
        nullif(lookup_source, '')          as dnsdb_lookup_source,
        nullif(looked_up_at, '')           as dnsdb_looked_up_at,
        nullif(notes, '')                  as dnsdb_notes
    from {{ ref('dnsdb_lookups') }}
)

select
    h.host,
    h.reg_domain,
    h.class,
    h.draws,
    h.drawn_by,
    h.n_runs,
    h.first_seen_ts,
    h.last_seen_ts,
    h.sample_family,

    -- priority for the browser DNSDB sweep: registrable first, by draw volume
    case when h.class = 'registrable' then 1 else 2 end as lookup_priority,

    -- active DNS (dig) + RDAP registration, from harness/dns_enrich.py
    d.resolves_now,
    d.a_records,
    d.aaaa_records,
    d.cname,
    d.ns_records,
    d.rdap_status,
    -- reconcile dig + RDAP: a domain that resolves is registered even if the
    -- registry's RDAP flakily 404s (common on .io/.cn). "available" (unregistered
    -- AND not resolving) is the clean sinkhole-candidate set for #6.
    case
        when d.rdap_status = 'registered'   then 'registered'
        when d.resolves_now                 then 'registered'
        when d.rdap_status = 'unregistered' then 'available'
        else 'unknown'
    end as reg_verdict,
    coalesce(d.whois_reg_date, i.reg_date)      as reg_date_final,
    d.whois_reg_date,
    d.whois_expiration,
    d.whois_registrar,
    d.resolved_at,

    -- Mnemonic passive DNS (historical)
    m.mn_observed,
    m.mn_count,
    m.mn_distinct_answers,
    m.mn_total_times,
    m.mn_first_seen,
    m.mn_last_seen,
    m.mn_rrtypes,
    m.mn_answers,

    -- highest-signal #6 flag: historically seen resolving AND now free to claim
    case
        when m.mn_observed and (
            case when d.rdap_status = 'registered' then 'registered'
                 when d.resolves_now then 'registered'
                 when d.rdap_status = 'unregistered' then 'available'
                 else 'unknown' end) = 'available'
        then true else false
    end as prior_use_and_available,

    -- prior keyless intel (Mnemonic pDNS + RDAP), from harness/pdns_intel.py
    i.pdns_exists,
    i.pdns_records,
    i.pdns_distinct_rdata,
    i.pdns_first_seen,
    i.pdns_last_seen,
    i.intel_dnsdb_count,
    i.reg_date,
    i.reg_expiration,
    i.registrar,
    i.intel_note,

    -- DNSDB passive DNS collected via the browser (filled into seed dnsdb_lookups)
    p.dnsdb_resolved,
    p.dnsdb_rrset_count,
    p.dnsdb_distinct_rdata,
    p.dnsdb_first_seen,
    p.dnsdb_last_seen,
    p.dnsdb_resolved_ips,
    p.dnsdb_lookup_source,
    p.dnsdb_looked_up_at,
    p.dnsdb_notes,

    (p.host is not null) as dnsdb_looked_up
from hosts h
left join intel    i on i.host = h.host
left join dns      d on d.host = h.host
left join mnemonic m on m.host = h.host
left join pdns     p on p.host = h.host
order by lookup_priority, h.draws desc, h.host
