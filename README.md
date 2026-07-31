# cause

cause provides a basic and argument-less API for triggering things in remote machines over HTTP with reasonable security.

## usage

Use behind a reverse proxy like caddy or nginx that provides TLS termination.

```sh
Usage: cause [OPTIONS]

Options:
  -c, --config <CONFIG>    Path to the configuration file [default: cause.toml]
  -a, --address <ADDRESS>  Address to listen on [default: 127.0.0.1]
  -p, --port <PORT>        Port to listen on [default: 3000]
  -h, --help               Print help
  -V, --version            Print version
```

Generating a key: `./key.sh <key>`

```sh
# it does the following:
# generate a yescrypt hash
HASH=$(mkpasswd -m yescrypt super53cr37)
# prepend a random 8-char key ID (public)
KEYID=$(head -c 4 /dev/urandom | xxd -p)
echo "${KEYID}:${HASH}" >> keys
```

Use the full key (`keyid.secret`) as the value in the `x-api-key` (by default) header.

## development

The example key in `example/keys` is `a1b2c3d4.dev`.
