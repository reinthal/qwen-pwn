-- Draw counts at the FQDN grain (full hostname). One row per distinct host
-- drawn by the model, across every farm run. Histogram source: order by draws.
select
    fqdn,
    reg_domain,
    tld,
    class,
    draws,
    drawn_by,
    n_runs,
    first_seen_ts,
    last_seen_ts
from {{ ref('int_host_classified') }}
order by draws desc, fqdn
