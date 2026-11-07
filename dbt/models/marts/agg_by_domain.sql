-- Draw counts at the registered-domain grain (eTLD+1). Collapses every subdomain
-- (fqdn) under its registration. Histogram source: order by draws.
select
    reg_domain,
    any_value(tld)                              as tld,
    sum(draws)                                  as draws,
    count(*)                                     as n_fqdns,
    list_sort(array_agg(distinct class))        as classes,
    -- dominant class = the class of the highest-draw fqdn under this domain
    arg_max(class, draws)                       as top_class,
    min(first_seen_ts)                          as first_seen_ts,
    max(last_seen_ts)                           as last_seen_ts
from {{ ref('int_host_classified') }}
group by reg_domain
order by draws desc, reg_domain
