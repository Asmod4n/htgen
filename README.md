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

A thread-per-connection generator spends more CPU per request than a
ring server spends answering one. Past a certain server, a benchmark
stops measuring the server and starts measuring the generator — and
raising its thread count only moves the wall, because the cost is per
request, not per thread.

Measured on one 4-vCPU box, same server, same route, TCP, `-c8`, 3 s,
against `h2load` (nghttp2), which is what the numbers below compare:

| | h2load | htgen |
|---|---|---|
| 1 request in flight | 66 929 rps | 212 097 rps |
| 64 streams | 631 573 rps | 2 109 802 rps |

htgen is built the way a modern server is: multishot recv out of a
provided buffer ring, `IORING_RECVSEND_BUNDLE` on that recv where the
kernel offers it, one ring enter carrying hundreds of completions.

The SEND side does not use bundles, and the reason is that it has
nothing to gain from them: a bundle exists to let one operation consume
several queued buffers, and htgen already concatenates a connection's
whole round into one buffer in user space, so the send is one SQE
either way. Using the kernel's mechanism instead would mean a provided
buffer ring per connection - a bundle takes a CONTIGUOUS run of buffer
ids for ONE socket, and connections interleave - which is a lot of
machinery to arrive at the same syscall count.

## Options

Install it if you would rather not type a path:

```
make install                      # /usr/local/bin/htgen
make install PREFIX=$HOME/.local  # ~/.local/bin/htgen
```

```
--host H --port P     where to connect, TCP
--sock PATH           ... or an AF_UNIX socket, instead of host/port
--conns N             connections to open (default 64)
--seconds S           how long to run (default 5)
--path P              request target (default /)
--host-header H       the Host header, and h2's :authority (default localhost)
--h2                  speak HTTP/2 with prior knowledge (RFC 9113 3.4)
--tls                 agree TLS 1.3 keys, hand them to the kernel, and
                      measure through kTLS. TCP only. Needs a build with
                      KTLS= (see Requirements); ALPN names h2 with --h2
                      and http/1.1 without.
--streams M           concurrent streams per connection, --h2 only (default 1)
--pipeline D          h1 requests in flight per connection (RFC 9112
                      9.3.2), h1 only (default 1)
--header NAME:VALUE   an extra request field, repeatable. Names are
                      lowercased, because RFC 9113 8.2 requires it of h2
                      and HPACK indexes the static table by that
                      spelling - so both protocols carry the same field.
--method M            the request method (default GET)
--body TEXT           request content, spelled on the command line
--body-file PATH      ... or read from a file. h1 announces it with
                      Content-Length (RFC 9110 8.6); h2 sends it as a
                      DATA frame after the HEADERS (RFC 9113 8.1). Over
                      h2 it is capped at 16384 bytes - past one stream
                      window this client would need WINDOW_UPDATE
                      handling it does not have yet, and it says so
                      rather than stalling mid-body.
--bufs N              buffers in the provided ring, power of two
                      (default 2048)
--buf-size N          bytes per buffer (default 4096). Both are here
                      because an empty ring is the first thing to
                      suspect when NEITHER end is at its limit: the
                      kernel answers -ENOBUFS, that connection's recv
                      has to be armed again, and it sits idle until it
                      is. `enobufs=` in the result line says whether
                      that ever happened, so the knob is turned on
                      evidence rather than on a hunch.
--latency             also measure per-request latency, and print
                      percentiles. Needs --pipeline 1: with a batch on
                      the wire there is ONE timestamp for every answer
                      in it, and a percentile taken from that is not a
                      latency - which is why the flag refuses instead
                      of printing one. Over h2 each stream is timed
                      separately, so --streams stays honest.
```

`--header` is what makes a run resemble a browser rather than a probe:
`Accept`, `Accept-Encoding` and `Accept-Language` are the fields a real
client sends, and a server may take a completely different path when
they are present.

One line of counts comes back:

```
responses=1173751 bad=0 seconds=3.000 rps=391249 bytes=210075179 MB/s=66.78 conns=32 streams=1 pipeline=1 method=GET proto=h1 bundles=1 bufs=2048/4096 enobufs=0 rearms=0
```

`enobufs` counts the times the buffer ring was empty when an answer
arrived; `rearms` counts multishot recvs that ended and had to be armed
again. Both zero is what a healthy run looks like. Either one climbing
while neither end is at 100% CPU is the explanation for the gap.

With `--latency`, a second line follows:

```
latency_us p50=85 p90=126 p99=172 p999=240 max=340 over65ms=0 n=191719
```

The histogram has one bucket per microsecond up to 65 ms, which covers
every answer a local server gives; anything past it is counted in
`over65ms` and a percentile that lands there prints `>65535` rather than
the cap dressed up as a measurement.

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
liburing, ls-hpack (HPACK, RFC 7541), picohttpparser. `--tls` needs one
more thing that is NOT a submodule: mruby-ktls and the OpenSSL it built.
See "TLS, through the kernel" below.

liburing is vendored rather than taken from the distro on purpose — the
system copy is routinely older than the ring features this tool exists to
use. Debian trixie ships 2.5; send/recv bundles arrived in 2.6. Build
with `USE_SYSTEM_URING=1` to use the system copy anyway; the two places
that need bundles are guarded, and the run says on startup what it lost.

## TLS, through the kernel

`--tls` measures an encrypted connection without a record layer in this
process. The handshake runs once per connection, before the ring sees
the descriptor: blocking reads and writes, keys agreed with
[mruby-ktls](https://github.com/Asmod4n/mruby-ktls)'s C library, and
then `setsockopt(TLS_TX | TLS_RX)`. From there the KERNEL encrypts, so
every send and recv in the measured loop is the same code as without
TLS — no copy through an encryption buffer, and the numbers stay
comparable.

It is off unless the build says otherwise, because the library needs an
OpenSSL that was built WITH kTLS and a distribution's usually was not
(Ubuntu's `libssl.so.3` exports no ktls symbol). mruby-ktls builds one
and keeps it:

```
make KTLS=~/mruby-ktls OPENSSL=~/mruby-ktls/build/openssl
```

Two things this arrangement means, and they belong in any number it
produces:

* The peer is not verified. `ktls_keys_client` carries no trust store —
  this is a load generator pointed at a machine you own.
* A socket the kernel owns answers **EIO** on `recv(2)` for any record
  that is not application data. The tickets a server writes right after
  its Finished are drained before the handover; a KeyUpdate in the
  middle of a run ends that connection and is counted in `bad`.

## What it does not do yet

Request content larger than one HTTP/2 stream window (16 KiB), which
would need WINDOW_UPDATE handling. Trailers. Several URLs in one run.
TLS on a unix socket — the kernel's record layer is a TCP ULP, so
`setsockopt(TCP_ULP, "tls")` there is ENOTSUP.

## License

Apache-2.0.
