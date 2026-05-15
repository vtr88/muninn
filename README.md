# Muninn Proxy

Muninn is a small terminal HTTP/HTTPS proxy written in C. It listens on
`127.0.0.1:13337`, forwards traffic without pausing it, and shows a simple TUI
with separate logs for client-to-server and server-to-client bytes.

It currently supports:

- Plain HTTP proxy forwarding.
- HTTPS `CONNECT` interception using a generated local CA.
- Dynamic per-host certificates for HTTPS MITM.
- A thread-per-connection network model.
- An ncurses TUI with two tabs:
  - `C->S`: client to server.
  - `S->C`: server to client.

Muninn is currently an observe-only proxy. It prints traffic, but it does not
pause, edit, replay, or drop requests.

## Build

Install a C compiler, ncurses development headers, OpenSSL development headers,
and pthread support, then run:

```sh
make
```

This creates `./muninn`.

## Run

```sh
./muninn
```

On first run, Muninn creates:

```text
muninn-ca-key.pem
muninn-ca-cert.pem
```

Import `muninn-ca-cert.pem` into your browser as a trusted certificate
authority. Do not share `muninn-ca-key.pem`; it is the private key used to sign
the fake per-site certificates.

Configure your browser or command-line client to use:

```text
HTTP proxy: 127.0.0.1
Port:       13337
```

For example:

```sh
curl -x http://127.0.0.1:13337 http://example.com/
```

For HTTPS testing with curl:

```sh
curl --cacert muninn-ca-cert.pem \
  -x http://127.0.0.1:13337 \
  https://example.com/
```

## TUI Controls

- `Tab`, left arrow, or right arrow: switch between `C->S` and `S->C`.
- `q`: quit.

## Notes

The code is intentionally closer to OpenBSD-style C than to a framework
project: explicit sockets, explicit TLS setup, explicit threads, and plain
structs. The source is heavily commented in Brazilian Portuguese so the proxy
flow can be studied directly.

This is a local debugging tool. Only import the Muninn CA in a browser profile
you use for testing.
