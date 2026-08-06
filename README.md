# cause

cause provides a basic and argument-less API for triggering things in remote machines over HTTP with reasonable security.

things to note:
- the process, once triggered, will run to completion/timeout even if the triggering party disconnects
- targets only linux systems
- intended to be behind a reverse proxy
- never expose cause directly to untrusted networks
- a `GET /` endpoint returns `200 OK` for load balancer probes and container health checks

## usage

```sh
Usage: cause [OPTIONS]

Options:
  -c, --config <CONFIG>    Path to the configuration file [default: cause.toml]
  -a, --address <ADDRESS>  Address to listen on [default: 127.0.0.1]
  -p, --port <PORT>        Port to listen on [default: 3000]
  -h, --help               Print help
  -V, --version            Print version
```

## configuration

cause is configured with a TOML file (default: `cause.toml`).

### `[global]` (optional)

all fields have defaults; unknown fields are rejected.

| option                     | default       | description                                                                                                                                                    |
|----------------------------|---------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `auth_header`              | `"x-api-key"` | HTTP header carrying the API key                                                                                                                               |
| `timeout`                  | `900`         | max runtime (seconds) of a triggered process before it is killed                                                                                               |
| `trusted_proxies`          | `[]`          | IPs of reverse proxies allowed to set `x-forwarded-for`; when the peer is trusted, the forwarded client IP is used for rate limiting/failure tracking          |
| `auth_semaphore_size`      | `4`           | max concurrent password-hash verifications (bounds CPU usage of auth)                                                                                          |
| `failure_threshold`        | `10`          | auth failures per IP within `failure_window_secs` before tarpitting kicks in                                                                                   |
| `failure_window_secs`      | `600`         | fixed window (seconds) for counting auth failures: the timer starts at the first failure and the counter resets once the window expires (not a rolling window) |
| `block_duration_secs`      | `600`         | duration (seconds) an IP remains blocked after exceeding the failure threshold                                                                                 |
| `tarpit_duration_ms`       | `500`         | delay (milliseconds) applied to every failed auth attempt and to requests from blocked IPs                                                                     |
| `rate_limit_per_second`    | `2`           | sustained per-IP request rate                                                                                                                                  |
| `rate_limit_burst`         | `5`           | per-IP burst allowance on top of the sustained rate                                                                                                            |
| `kill_grace_secs`          | `1`           | grace period (seconds) between SIGTERM and SIGKILL when terminating a timed-out process                                                                        |
| `drain_grace_secs`         | `1`           | post-exit grace period for draining the output buffer of the child process                                                                                     |
| `max_line_length`          | `65536`       | max length (bytes) of a single output line from the triggered process; longer lines are truncated                                                              |
| `failure_max_entries`      | `100000`      | max IPs tracked in the failure table (bounds memory)                                                                                                           |
| `auth_acquire_timeout_ms`  | `2000`        | max time (milliseconds) to wait for an auth verification slot before rejecting                                                                                 |
| `max_inflight_auth_per_ip` | `2`           | max concurrent auth attempts per IP                                                                                                                            |
| `max_auth_queue_depth`     | `64`          | max requests waiting for an auth slot before new ones are rejected                                                                                             |

### `[routes.<name>]`

each route becomes a `POST /<name>` endpoint. route names may only contain ASCII alphanumerics, `_`, and `-`.

| option        | required          | description                                                                               |
|---------------|-------------------|-------------------------------------------------------------------------------------------|
| `shell`       | yes               | path to the executable to run; must exist, be a regular file, and have an execute bit set |
| `args`        | yes               | arguments passed to the executable                                                        |
| `keys`        | yes               | path to the keys file (see below) authorized for this route                               |
| `concurrency` | no (default `1`)  | max concurrent executions of this route                                                   |

example:

```toml
[global]
auth_header = "x-api-key"
timeout = 900

[routes.hello]
shell = "/usr/bin/bash"
args = [ "examples/hello.sh" ]
keys = "examples/keys"
concurrency = 1
```

#### generating a key

for convenience and development, use: `./key.sh <key>`
(it is not advised to leave keys in shell history though)

```sh
# rolling your own tool for key generation

# generate a yescrypt hash
HASH=$(mkpasswd -m yescrypt super53cr37)

# prepend a random 8-char key id
KEYID=$(head -c 4 /dev/urandom | xxd -p)

# output in the correct format into some key list
echo "${KEYID}:${HASH}" >> keys
```

use the full key (`keyid.secret`) as the value in the `x-api-key` (by default) header.

## development

- the example key in `examples/keys` is `a1b2c3d4.dev`.
- running the examples:
  - `cargo run`
  - `curl -i -XPOST -H 'x-api-key: a1b2c3d4.dev' http://localhost:3000/hello`
  - `curl -i -XPOST -H 'x-api-key: a1b2c3d4.dev' http://localhost:3000/loop`
