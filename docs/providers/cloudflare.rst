cloudflare
    * `auth_username` specify email address for authentication (for Global API key only)

    * `auth_token` specify token for authentication (Global API key or API token)

    * `zone_id` specify the zone id (if set, API token can be scoped to the target zone)


```{note}
There are two ways to provide an authentication granting edition to the target CloudFlare DNS zone.

1 - A Global API key, with --auth-username and --auth-token flags.

2 - An unscoped API token (permissions Zone:Zone(read) + Zone:DNS(edit) for all zones), with --auth-token flag.

3 - A scoped API token (permissions Zone:Zone(read) + Zone:DNS(edit) for one zone), with --auth-token and --zone-id flags.
Finding zone_id value is explained in CloudFlare `Doc <https://developers.cloudflare.com/fundamentals/setup/find-account-and-zone-ids/>`_

```

