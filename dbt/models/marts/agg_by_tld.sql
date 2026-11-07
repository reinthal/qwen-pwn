-- Draw counts at the TLD grain. Only hosts with a real alpha TLD (IPs, localhost
-- and single-label hosts are excluded, tld is null there). Histogram source.
select
    tld,
    sum(draws)                      as draws,
    count(distinct reg_domain)      as n_domains,
    count(*)                        as n_fqdns
from {{ ref('int_host_classified') }}
where tld is not null
group by tld
order by draws desc, tld
