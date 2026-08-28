# htgen

An HTTP/1.1 and HTTP/2 load generator on io_uring. One ring, one thread,
no configuration language.

```sh
git clone --recursive https://github.com/Asmod4n/htgen
cd htgen && make

./htgen --host 127.0.0.1 --port 8080 --conns 64 --seconds 10
./htgen --sock /tmp/server.sock --h2 --streams 32
```

## Why

`wrk` costs about three times as much CPU per request as a ring server
spends answering one. Past a certain server, a benchmark stops measuring
the server and starts measuring `wrk` — and raising its thread count only
moves the wall, because the cost is per request, not per thread.

Measured on one 4-vCPU box, same server, same route, TCP, `-c8`, 3 s:

| | h2load | htgen |
|---|---|---|
| 1 request in flight | 66 929 rps | 212 097 rps |
| 64 streams | 631 573 rps | 2 109 802 rps |

htgen is built the way a modern server is: multishot recv out of a
provided buffer ring, send bundles where the kernel offers them, one ring
enter carrying hundreds of completions.

## Options

```
--host H --port P     where to connect, TCP
--sock PATH           ... or an AF_UNIX socket, instead of host/port
--conns N             connections to open (default 64)
--seconds S           how long to run (default 5)
--path P              request target (default /)
--host-header H       the Host header, and h2's :authority (default localhost)
--h2                  speak HTTP/2 with prior knowledge (RFC 9113 3.4)
--streams M           concurrent streams per connection, --h2 only (default 1)
--pipeline D          h1 requests in flight per connection (RFC 9112
                      9.3.2), h1 only (default 1)
--header NAME:VALUE   an extra request field, repeatable. Names are
                      lowercased, because RFC 9113 8.2 requires it of h2
                      and HPACK indexes the static table by that
                      spelling - so both protocols carry the same field.
```

`--header` is what makes a run resemble a browser rather than a probe:
`Accept`, `Accept-Encoding` and `Accept-Language` are the fields a real
client sends, and a server may take a completely different path when
they are present.

One line of counts comes back:

```
responses=1173751 bad=0 seconds=3.000 rps=391249 bytes=210075179 MB/s=66.78 conns=32 streams=1 pipeline=1 proto=h1 bundles=1
```

`bytes` is every byte the kernel handed back, and `MB/s` is that over
the run. Two servers can reach the same rps while moving very different
amounts of data - a thousand small answers against one large one - and
this is the column that tells them apart.

`bad` counts what a load generator must never quietly absorb: a non-2xx
answer, a refused stream, an unparseable response, an HPACK decoder that
lost sync. A run with `bad` above zero measured a server in trouble, not
its floor.

`bundles` says whether the kernel granted send/recv bundles. Set
`HTGEN_BUNDLE=0` to turn them off and price them.

## Requirements

Linux with io_uring, a C++20 compiler. Everything else is a submodule:
liburing, ls-hpack (HPACK, RFC 7541), picohttpparser.

liburing is vendored rather than taken from the distro on purpose — the
system copy is routinely older than the ring features this tool exists to
use. Debian trixie ships 2.5; send/recv bundles arrived in 2.6. Build
with `USE_SYSTEM_URING=1` to use the system copy anyway; the two places
that need bundles are guarded, and the run says on startup what it lost.

## What it does not do yet

Latency percentiles. A pipelining mode. Anything but GET. Request bodies.
TLS — and that one is unlikely to arrive here, because measuring a TLS
handshake is a different tool's job.

## License

Apache-2.0.
