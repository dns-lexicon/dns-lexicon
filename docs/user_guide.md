# User guide

## Installation

### Using pip

:::{warning}
It is strongly advised with pip to install Lexicon in a Python virtual environment,
in order to avoid interference between Python modules preinstalled on your system as
OS packages and modules installed by pip (see <https://docs.python-guide.org/dev/virtualenvs/>).
:::

To use Lexicon as a CLI application, do the following:

```bash
$ pip install dns-lexicon
```

Some providers (like Route53 and TransIP) require additional dependencies. You can install
the [provider specific dependencies] separately:

```bash
$ pip install dns-lexicon[route53]
```

To install lexicon with the additional dependencies of every provider, do the following:

```bash
$ pip install dns-lexicon[full]
```

You can also install the latest version from the repository directly.

```bash
$ pip install git+https://github.com/dns-lexicon/dns-lexicon.git
```

and with Route 53 provider dependencies:

```bash
$ pip install git+https://github.com/dns-lexicon/dns-lexicon.git#egg=dns-lexicon[route53]
```

### Using Docker

Lexicon is prepackaged as a Docker image available in the Github Container Registry. The name of the image is `ghcr.io/dns-lexicon/dns-lexicon`.

You can either use the latest version available, or pin to a specific version (eg. `ghcr.io/dns-lexicon/dns-lexicon:3.20.1` to use version `3.20.1`).

Lexicon CLI flags can be passed directly to the Docker image to execute Lexicon:

```bash
$ docker run --rm ghcr.io/dns-lexicon/dns-lexicon --help
```

### Using your OS package manager

Lexicon is available in various Linux distributions. Please search for `lexicon` or `dns-lexicon` package in <https://pkgs.org>.

## Usage

```bash
$ lexicon -h
usage: lexicon [-h] [--version] [--delegated DELEGATED] [--config-dir CONFIG_DIR] [--resolve-zone-name]
              {aliyun,...,zonomi}
              ...

Create, Update, Delete, List DNS entries

positional arguments:
  {aliyun,...,zonomi}
                        specify the DNS provider to use
    aliyun              aliyun provider
    ...
    zonomi              zonomi provider

optional arguments:
  -h, --help            show this help message and exit
  --version             show the current version of lexicon
  --delegated DELEGATED
                        specify the delegated domain (may not needed if --resolve-zone-name is set)
  --config-dir CONFIG_DIR
                        specify the directory where to search lexicon.yml and lexicon_[provider].yml configuration files (default: current directory).
  --resolve-zone-name   trigger an active resolution of the zone name for the given domain using DNS queries
```

Using the lexicon CLI is pretty simple:

```bash
# setup provider environmental variables:
export LEXICON_CLOUDFLARE_USERNAME="myusername@example.com"
export LEXICON_CLOUDFLARE_TOKEN="cloudflare-api-token"

# list all TXT records on cloudflare
lexicon cloudflare list example.com TXT

# create a new TXT record on cloudflare
lexicon cloudflare create www.example.com TXT --name="_acme-challenge.www.example.com." --content="challenge token"

# delete a  TXT record on cloudflare
lexicon cloudflare delete www.example.com TXT --name="_acme-challenge.www.example.com." --content="challenge token"
lexicon cloudflare delete www.example.com TXT --identifier="cloudflare record id"
```

## Configuration

### Authentication

Most supported DNS services provide an API token, however each service implements authentication differently.
Lexicon attempts to standardize authentication around the following CLI flags:

- `--auth-username` - For DNS services that require it, this is usually the account id or email address
- `--auth-password` - For DNS services that do not provide an API token, this is usually the account password
- `--auth-token` - This is the most common auth method, the API token provided by the DNS service

You can see all the `--auth-*` flags for a specific service by reading the DNS service specific help:
`lexicon cloudflare -h`

### Environmental variables

Instead of providing authentication information via the CLI, you can also specify them via environmental
variables. Every DNS service and auth flag maps to an environmental variable as follows:
`LEXICON_{DNS Provider Name}_{Auth Type}`

So instead of specifying `--auth-username` and `--auth-token` flags when calling `lexicon cloudflare ...`,
you could instead set the `LEXICON_CLOUDFLARE_USERNAME` and `LEXICON_CLOUDFLARE_TOKEN` environmental variables.

Injection of Lexicon general options also works with environment variables, using the `LEXICON_` prefix: for
instance `LEXICON_DELEGATED` can be used to setup the `--delegated` option (see next paragraph for the purpose
of this option).

```bash
LEXICON_DELEGATED=foo.example.com
```

### Resolution of the zone name

Given the provided domain, Lexicon must determine what is the actual zone name that needs to be queried.

If the decision is "easy" for second-level domains (like `example.com`), it is not the case for higher level
domains. For instance `example.com` DNS zone could declare a delegation of subdomain `sub.example.com` to
another DNS zone. In this case, a request done to `sub.example.com` must correctly that the zone name is
`sub.example.com` and not `example.com`.

Lexicon provides two ways to deal with this situation.

#### TLDextract & `--delegate`

By default the [tldextract] library is used by Lexicon to guess the actual zone name from well known top-level
domains (aka TLDs). This works well for second-level domains, like guessing that zone name for `www.domain.net`
is `domain.net`.

Lexicon stores `tldextract` cache by default in `~/.lexicon_tld_set` where `~` is the current user's home
directory. You can change this path using the `TLDEXTRACT_CACHE_PATH` environment variable.

For instance, to store `tldextract` cache in `/my/path/to/tld_cache`, you can invoke Lexicon
like this from a Linux shell:

```bash
TLDEXTRACT_CACHE_PATH=/my/path/to/tld_cache lexicon myprovider create www.example.net TXT ...
```

For higher-level domains, like `sub.domain.net` defined to a specific DNS zone, Lexicon would improperly guess that
the zone name is `domain.net`. To instruct Lexicon here, please use the `--delegated` flag with the actual zone name.

For instance:

```bash
# Create the TXT entry "bar" on FQDN "foo.sub.domain.net" in DNS zone of domain "sub.domain.net"
lexicon --delegated=sub.domain.net cloudflare create sub.domain.net TXT --name=foo --content=bar
```

#### Use of `--resolve-zone-name`

A more modern approach introduced with Lexicon 3.17.0 is to leverage `dnspython` capacities to lookup on the DNS
servers what is the actual zone name of a given domain. In this case `tldextract` is not used.

In the example given to the previous section, Lexicon will then be able to directly guess that the zone name is
`sub.domain.net` and not `domain.net`.

This option is disabled by default. To activate it, you can pass the flag `--resolve-zone-name` to Lexicon.

For instance:

```bash
# Create the TXT entry "bar" on FQDN "foo.sub.domain.net" in DNS zone of domain "sub.domain.net"
lexicon --resolve-zone-name cloudflare create sub.domain.net TXT --name=foo --content=bar
```

In most cases, the `--delegated` flag is not needed. However you can still use it if needed to override the
resolved zone name.

## Integration

Lexicon can be integrated with various tools and process to help handling DNS records.

### Let's Encrypt instructions

Lexicon has an example [dehydrated hook file] that you can use for any supported provider.
All you need to do is set the PROVIDER env variable.

```bash
PROVIDER=cloudflare dehydrated --cron --hook dehydrated.default.sh --challenge dns-01
```

Lexicon can also be used with [Certbot] and the included [Certbot hook file] (requires configuration).

### Docker

There is an included example Dockerfile that can be used to automatically generate certificates for your website.

[certbot]: https://certbot.eff.org/
[certbot hook file]: examples/certbot.default.sh
[dehydrated hook file]: examples/dehydrated.default.sh
[provider specific dependencies]: https://github.com/dns-lexicon/dns-lexicon/blob/main/setup.py#L34-L44
[tldextract]: https://pypi.org/project/tldextract/
