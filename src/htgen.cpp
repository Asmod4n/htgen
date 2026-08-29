// htgen: an HTTP load generator on io_uring. One ring, one thread.
//
// A thread-per-core client spends more CPU per request than a modern
// server spends answering one, and past a certain server that is what a
// benchmark ends up measuring. htgen is built the way such a server is:
// multishot recv out of a provided buffer ring, send bundles where the
// kernel offers them, one ring enter carrying hundreds of completions,
// and one outstanding request per connection unless asked for more.
//
//   htgen --sock PATH [--conns N] [--seconds S] [--path P] [--host H]
//   htgen --host 127.0.0.1 --port 8123 [...]
//   htgen --sock PATH --h2 [--streams M]
//
// The h2 half speaks RFC 9113 with prior knowledge (3.4, no upgrade
// dance). The frame layer is h2_wire.hpp next door; what lives here is
// only what a CLIENT does with it - which pseudo-fields a request
// carries, that stream ids are odd, and that a stream ending is a
// response.
//
// Prints one line of counts.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <memory>
#include <string_view>
#include <vector>
#include <utility>

#include "liburing.h"

extern "C" {
#include "picohttpparser.h"
}

#include "h2_wire.hpp"

namespace {

using namespace htgen;

// Ring geometry. 2048 buffers of 4 KiB is enough that a burst of small
// responses lands in one completion batch without the pool running dry,
// and small enough to stay in cache.
// The provided buffer ring's geometry. Both are SETTABLE (--bufs,
// --buf-size) because they are the first thing to suspect when neither
// end is at its limit: an empty ring answers -ENOBUFS, the recv has to
// be armed again, and that connection sits idle until it is - which
// looks exactly like a slow peer. The count must stay a power of two;
// io_uring_buf_ring_mask depends on it.
constexpr unsigned kBufCountDefault = 2048;
constexpr unsigned kBufSizeDefault = 4096;
constexpr unsigned kBufGroup = 1;

// RFC 7541 4.2: SETTINGS_HEADER_TABLE_SIZE has no upper bound in either
// RFC, and it arrives from the peer - so the ceiling on what our encoder
// will allocate for it is ours to set.
constexpr uint32_t kEncTableMax = 65536;
// RFC 7541: the room ONE decoded field may take. The same ceiling the
// per-field window always had - what changed is that every field now
// reuses it instead of the next 4 KiB along.
constexpr unsigned kHdrFieldMax = 4096;
constexpr unsigned kSqEntries = 16384;

// RFC 9113 6.9: the client's own receive window. Opened once to the
// ceiling and topped up a quarter of it at a time, so flow control never
// becomes the thing being measured. A benchmark that stalls on a window
// measures the window.
constexpr int64_t kWindowTopUp = kH2WindowCeiling / 4;

// RFC 9113 5.1.1: client ids are odd and never reused. Past this one a
// connection has no ids left; it stops asking and says so rather than
// quietly carrying on with an id the peer must reject.
constexpr uint32_t kLastClientId = 0x7ffffffd;

enum : uint8_t { kOpRecv = 1, kOpSend = 2 };

// A window onto memory somebody else owns, with the three operations the
// wire paths used a std::string for. There is no allocation here and no
// growth: every buffer is carved once, at startup, out of ONE block, and
// a write that would not fit is a bug the run says out loud rather than
// a silent realloc in the middle of a measurement.
struct Buf {
  char* p = nullptr;
  size_t len = 0;
  size_t cap = 0;

  void bind(char* mem, size_t bytes) { p = mem; cap = bytes; len = 0; }
  void clear() { len = 0; }
  bool empty() const { return len == 0; }
  size_t size() const { return len; }
  const char* data() const { return p; }
  char* data() { return p; }

  void append(const char* s, size_t n) {
    if (len + n > cap) {
      std::fprintf(stderr, "htgen: buffer too small - %zu + %zu > %zu\n", len, n, cap);
      std::exit(1);
    }
    std::memcpy(p + len, s, n);
    len += n;
  }
  void append(const Buf& o) { append(o.p, o.len); }
  void assign(const char* s, size_t n) { len = 0; append(s, n); }
  void swap(Buf& o) {
    char* tp = p; size_t tl = len, tc = cap;
    p = o.p; len = o.len; cap = o.cap;
    o.p = tp; o.len = tl; o.cap = tc;
  }
};

// What points into argv or into the one block: a view, never an owner.
// std::string_view is exactly this and allocates nothing, so it is the
// spelling used - the wire paths below read .data()/.size() and copy
// nothing.
using Span = std::string_view;

inline uint64_t tag(uint8_t op, uint32_t idx) {
  return (static_cast<uint64_t>(op) << 56) | idx;
}

int64_t now_ns() {
  struct timespec t {};
  ::clock_gettime(CLOCK_MONOTONIC, &t);
  return static_cast<int64_t>(t.tv_sec) * 1000000000 + t.tv_nsec;
}

// RFC 9113 4.1: a frame with no payload of its own - SETTINGS ack, and
// the shape every control frame here is appended in.
void put_frame(Buf& out, uint32_t len, uint8_t type, uint8_t flags, uint32_t stream) {
  unsigned char fh[kH2FrameHeaderLen];
  h2_put_frame_header(fh, len, type, flags, stream);
  out.append(reinterpret_cast<const char*>(fh), sizeof(fh));
}

void put_u32(Buf& out, uint32_t v) {
  const unsigned char b[4] = {static_cast<unsigned char>(v >> 24),
                              static_cast<unsigned char>(v >> 16),
                              static_cast<unsigned char>(v >> 8),
                              static_cast<unsigned char>(v)};
  out.append(reinterpret_cast<const char*>(b), sizeof(b));
}

// RFC 9113 5/6 and RFC 7541: everything one h2 connection must remember.
// The HPACK tables are the reason this is per connection and not per
// process - two connections encode the same request into different bytes.
struct H2Conn {
  struct lshpack_enc enc;
  struct lshpack_dec dec;
  // What is left of a frame that did not fit in one buffer, and nothing
  // else: frames are parsed WHERE THEY LIE in the provided buffer, so a
  // run copies only the few bytes that straddle a boundary rather than
  // every byte it receives.
  Buf carry;
  // RFC 9113 6.10: a block across CONTINUATIONs, and ONLY then - a
  // HEADERS that already carries END_HEADERS is decoded where it lies.
  Buf frag;
  bool frag_end_stream = false;
  char* hdrbuf = nullptr;   // where ONE field lands while it is read
  size_t hdrbuf_cap = 0;
  // The four pseudo-fields do not change within a run, so the block they
  // encode to stops changing as soon as ls-hpack has them in its dynamic
  // table: from then on it emits indexed references and the bytes repeat.
  // Kept and re-emitted with a fresh stream id, the way the SERVER keeps
  // its answer head instead of encoding it again per request.
  Buf hdr_block;
  bool hdr_frozen = false;
  uint32_t next_id = 1;
  uint32_t open = 0;       // streams in flight
  int64_t window_used = 0; // DATA counted against the connection window
  bool done = false;       // GOAWAY seen, or the connection broke

  H2Conn() {
    lshpack_enc_init(&enc);
    lshpack_dec_init(&dec);
  }
  ~H2Conn() {
    lshpack_enc_cleanup(&enc);
    lshpack_dec_cleanup(&dec);
  }
  H2Conn(const H2Conn&) = delete;
  H2Conn& operator=(const H2Conn&) = delete;
};

// One connection: what it still owes of the response it is reading, what
// it still owes the wire, and - for h2 - the frame state above.
// RFC-free, and deliberately not a sorted sample vector: at a few
// million answers a second, keeping every latency would cost more RAM
// than the run. One bucket per microsecond up to 65 ms covers every
// answer a local server gives; what lands beyond it is counted apart
// and SAID, never folded into a percentile that would then be a guess.
struct Latency {
  static constexpr uint32_t kBuckets = 1u << 16;  // 0..65535 us
  uint64_t* us = nullptr;
  uint64_t over = 0;
  uint64_t n = 0;
  uint64_t max_us = 0;

  void bind(uint64_t* mem) { us = mem; }

  void add(int64_t ns) {
    const uint64_t v = static_cast<uint64_t>(ns < 0 ? 0 : ns) / 1000;
    n++;
    if (v > max_us) max_us = v;
    if (v >= kBuckets) { over++; return; }
    us[v]++;
  }

  // The rank-th sample, counted from the low end. Returns kBuckets when
  // the rank falls into the overflow, so the caller can say ">65ms"
  // instead of printing the cap as if it were the answer.
  uint64_t quantile(double q) const {
    if (n == 0) return 0;
    const uint64_t want = static_cast<uint64_t>(q * static_cast<double>(n));
    uint64_t seen = 0;
    for (uint32_t i = 0; i < kBuckets; i++) {
      seen += us[i];
      if (seen > want) return i;
    }
    return kBuckets;
  }
};

struct Conn {
  int fd = -1;
  size_t body_left = 0;   // RFC 9110 8.6: content still to arrive
  bool in_body = false;
  Buf carry;              // only used when a HEAD spans two buffers
  uint64_t done = 0;
  Buf out;                // queued for the wire, nothing in flight yet
  Buf wire;               // what the send in flight is reading from
  size_t sent_at = 0;     // how much of `wire` the kernel has taken
  bool sending = false;
  bool queued = false;    // already in Run::to_send this round
  bool dead = false;
  // --latency only. h1 carries one timestamp because one request is in
  // flight; h2 carries one per open stream, because they finish in any
  // order and a shared timestamp would be the batch's, not the
  // request's.
  int64_t sent_ns = 0;
  std::vector<std::pair<uint32_t, int64_t>> inflight;
  // The slice of the one block this connection's h2 buffers live in;
  // H2Conn owns no memory of its own.
  char* h2_mem = nullptr;
  std::unique_ptr<H2Conn> h2;
};

struct Run {
  struct io_uring ring {};
  struct io_uring_buf_ring* br = nullptr;
  char* pool = nullptr;
  unsigned buf_count = kBufCountDefault;
  unsigned buf_size = kBufSizeDefault;
  // What the ring running dry costs, counted rather than assumed: one
  // -ENOBUFS is one connection idle until its recv is armed again.
  uint64_t enobufs = 0;
  // A multishot recv that ended and had to be armed again. Normal at
  // a connection's end, a symptom in the middle of a run.
  uint64_t rearms = 0;
  std::vector<Conn> conns;
  std::vector<int> fds;
  Buf request;            // h1: the constant line; h2: unused
  Span path;
  Span authority;
  bool h2 = false;
  uint32_t streams = 1;
  bool bundles = false;
  unsigned replenish = 0;
  uint64_t responses = 0;
  uint64_t bad = 0;
  // Every byte the kernel handed us, counted where it arrives. A server
  // that answers 1000 small files and one that answers one large one can
  // reach the same rps with wildly different work, and only this column
  // tells them apart - it is what bench/assets.sh measures.
  uint64_t rx_bytes = 0;
  // And what went the other way. An upload run pushes gigabytes and
  // receives a 204: without this the MB/s column describes the answers
  // and says nothing about the thing being measured.
  uint64_t tx_bytes = 0;
  // h1 pipelining: how many requests ride one write. 1 = one in flight,
  // which is what every measurement before this defaulted to.
  uint32_t pipeline = 1;
  // Extra request fields, spelled once. h1 keeps them in `request`; h2
  // encodes them after the pseudo-fields (RFC 9113 8.3: pseudo-fields
  // come first).
  Span header_name[32];
  Span header_val[32];
  size_t nheaders = 0;
  // RFC 9110 9: the method, and the content a request carries. GET with
  // no content is the default and the only shape htgen had.
  Span method{"GET", 3};
  Span body{};
  bool latency = false;
  Latency lat;
  std::vector<uint32_t> to_send;

  struct io_uring_sqe* sqe() {
    struct io_uring_sqe* s = io_uring_get_sqe(&ring);
    if (s != nullptr) return s;
    io_uring_submit(&ring);
    s = io_uring_get_sqe(&ring);
    if (s == nullptr) {
      std::fprintf(stderr, "htgen: SQ stuck after submit\n");
      std::exit(1);
    }
    return s;
  }

  void arm_recv(uint32_t idx) {
    struct io_uring_sqe* s = sqe();
    io_uring_prep_recv_multishot(s, static_cast<int>(idx), nullptr, 0, 0);
    s->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
    s->buf_group = kBufGroup;
#ifdef IORING_RECVSEND_BUNDLE
    if (bundles) s->ioprio |= IORING_RECVSEND_BUNDLE;
#endif
    io_uring_sqe_set_data64(s, tag(kOpRecv, idx));
  }

  // One send in flight per connection: what is queued waits in `out`,
  // what the kernel is reading sits still in `wire`. Without the split
  // an append could move the buffer under a send already submitted.
  void arm_send(uint32_t idx) {
    Conn& c = conns[idx];
    if (c.dead || c.sending || c.out.empty()) return;
    c.wire.swap(c.out);
    c.out.clear();
    c.sent_at = 0;
    c.sending = true;
    if (latency && !h2 && c.sent_ns == 0) c.sent_ns = now_ns();
    struct io_uring_sqe* s = sqe();
    io_uring_prep_send(s, static_cast<int>(idx), c.wire.data(), c.wire.size(), MSG_NOSIGNAL);
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, tag(kOpSend, idx));
  }

  void queue(uint32_t idx) {
    Conn& c = conns[idx];
    if (c.queued || c.dead) return;
    c.queued = true;
    to_send.push_back(idx);
  }

  // A short send is lawful; the rest of the buffer goes out from where
  // the kernel stopped. h1's 40-byte line never saw one, an h2 round of
  // several frames can.
  void on_send(uint32_t idx, struct io_uring_cqe* cqe) {
    Conn& c = conns[idx];
    if (cqe->res <= 0) {
      c.dead = true;
      c.sending = false;
      return;
    }
    tx_bytes += static_cast<uint64_t>(cqe->res);
    c.sent_at += static_cast<size_t>(cqe->res);
    if (c.sent_at < c.wire.size()) {
      struct io_uring_sqe* s = sqe();
      io_uring_prep_send(s, static_cast<int>(idx), c.wire.data() + c.sent_at,
                         c.wire.size() - c.sent_at, MSG_NOSIGNAL);
      s->flags |= IOSQE_FIXED_FILE;
      io_uring_sqe_set_data64(s, tag(kOpSend, idx));
      return;
    }
    c.wire.clear();
    c.sent_at = 0;
    c.sending = false;
    if (!c.out.empty()) queue(idx);
  }

  // RFC 9112 3: count RESPONSES, not bytes - a head, then exactly the
  // content its Content-Length promised, then the next request goes out.
  //
  // Parses where the bytes lie and returns how many it consumed. It NEVER
  // touches the carry: the carry aliasing itself is what the old shape
  // got wrong - it appended a slice of the carry to the carry and then
  // recursed into it.
  size_t h1_parse(uint32_t idx, const char* base, size_t n) {
    Conn& c = conns[idx];
    size_t at = 0;
    while (at < n) {
      if (c.in_body) {
        const size_t have = n - at;
        const size_t take = have < c.body_left ? have : c.body_left;
        c.body_left -= take;
        at += take;
        if (c.body_left == 0) {
          c.in_body = false;
          h1_complete(idx);
        }
        continue;
      }
      int minor = 0, status = 0;
      const char* msg = nullptr;
      size_t msg_len = 0;
      struct phr_header hdr[64];
      size_t nhdr = sizeof(hdr) / sizeof(hdr[0]);
      const int r = phr_parse_response(base + at, n - at, &minor, &status, &msg, &msg_len,
                                       hdr, &nhdr, 0);
      if (r == -2) break;            // an incomplete head - carry it
      if (r < 0) {
        bad++;
        return n;                    // unparseable: drop what is here
      }
      size_t clen = 0;
      for (size_t i = 0; i < nhdr; i++) {
        if (hdr[i].name_len == 14 && strncasecmp(hdr[i].name, "Content-Length", 14) == 0) {
          // RFC 9110 8.6: the field value is DIGIT+. Read where it lies -
          // strtoull would want a terminator this buffer does not have.
          clen = 0;
          for (size_t k = 0; k < hdr[i].value_len; k++) {
            const char d = hdr[i].value[k];
            if (d < '0' || d > '9') { clen = 0; break; }
            clen = clen * 10 + static_cast<size_t>(d - '0');
          }
        }
      }
      at += static_cast<size_t>(r);
      if (clen == 0) {
        h1_complete(idx);
      } else {
        c.in_body = true;
        c.body_left = clen;
      }
    }
    return at;
  }

  // The carry is the ONLY copy this path makes, and only of the bytes
  // that straddle a buffer boundary.
  void h1_feed(uint32_t idx, const char* p, size_t n) {
    Conn& c = conns[idx];
    if (c.carry.empty()) {
      const size_t used = h1_parse(idx, p, n);
      if (used < n) c.carry.assign(p + used, n - used);
      return;
    }
    c.carry.append(p, n);
    const size_t used = h1_parse(idx, c.carry.data(), c.carry.size());
    if (used == c.carry.size()) {
      c.carry.clear();
    } else if (used != 0) {
      const size_t rest = c.carry.size() - used;
      std::memmove(c.carry.data(), c.carry.data() + used, rest);
      c.carry.len = rest;
    }
  }

  void h1_complete(uint32_t idx) {
    Conn& c = conns[idx];
    c.done++;
    responses++;
    if (latency) {
      lat.add(now_ns() - c.sent_ns);
      c.sent_ns = now_ns();
    }
    c.out.append(request);
    queue(idx);
  }

  // RFC 9113 3.4: the client's half of the preface, then the two windows
  // opened wide - SETTINGS for every stream to come, one WINDOW_UPDATE
  // for the connection, whose 65535 is not settable any other way.
  void h2_open(uint32_t idx) {
    Conn& c = conns[idx];
    c.h2 = std::make_unique<H2Conn>();
    char* m = c.h2_mem;
    c.h2->carry.bind(m, kH2MaxFrameSize + kH2FrameHeaderLen);
    m += kH2MaxFrameSize + kH2FrameHeaderLen;
    c.h2->frag.bind(m, 64 * 1024);
    m += 64 * 1024;
    c.h2->hdrbuf = m;
    c.h2->hdrbuf_cap = 64 * 1024;
    m += 64 * 1024;
    c.h2->hdr_block.bind(m, 1024);
    c.out.append(kH2Preface, kH2PrefaceLen);
    // RFC 9113 6.5.1: two settings, six bytes each, spelled on the stack.
    const uint32_t win = static_cast<uint32_t>(kH2WindowCeiling);
    const unsigned char sets[12] = {
        0, static_cast<unsigned char>(kH2SettingsEnablePush), 0, 0, 0, 0,
        0, static_cast<unsigned char>(kH2SettingsInitialWindowSize),
        static_cast<unsigned char>(win >> 24), static_cast<unsigned char>(win >> 16),
        static_cast<unsigned char>(win >> 8), static_cast<unsigned char>(win)};
    put_frame(c.out, sizeof(sets), kH2Settings, 0, 0);
    c.out.append(reinterpret_cast<const char*>(sets), sizeof(sets));
    put_frame(c.out, 4, kH2WindowUpdate, 0, 0);
    put_u32(c.out, static_cast<uint32_t>(kH2WindowCeiling - kH2DefaultWindow));
  }

  // RFC 9113 8.3: one request is one HEADERS frame - four pseudo-fields,
  // END_STREAM because a GET has no content. After the first the dynamic
  // table has all four, so the frame that follows is a handful of bytes.
  void h2_request(uint32_t idx) {
    Conn& c = conns[idx];
    H2Conn& h = *c.h2;
    if (h.next_id > kLastClientId) {
      h.done = true;
      return;
    }
    if (h.hdr_frozen) {
      const uint32_t id = h.next_id;
      h.next_id += 2;
      if (latency) c.inflight.emplace_back(id, now_ns());
      const uint8_t hflags =
          body.empty() ? (kH2FlagEndHeaders | kH2FlagEndStream) : kH2FlagEndHeaders;
      put_frame(c.out, static_cast<uint32_t>(h.hdr_block.size()), kH2Headers, hflags, id);
      c.out.append(h.hdr_block);
      if (!body.empty()) {
        put_frame(c.out, static_cast<uint32_t>(body.size()), kH2Data, kH2FlagEndStream, id);
        c.out.append(body.data(), body.size());
      }
      h.open++;
      return;
    }
    unsigned char buf[1024];
    unsigned char* ep = buf;
    unsigned char* const eend = buf + sizeof(buf);
    const bool ok =
        h2_enc_field(&h.enc, ep, eend, ":method", 7, method.data(), method.size()) &&
        h2_enc_field(&h.enc, ep, eend, ":scheme", 7, "http", 4) &&
        h2_enc_field(&h.enc, ep, eend, ":authority", 10, authority.data(), authority.size()) &&
        h2_enc_field(&h.enc, ep, eend, ":path", 5, path.data(), path.size());
    bool ok_hdrs = ok;
    for (size_t k = 0; k < nheaders && ok_hdrs; k++) {
      ok_hdrs = h2_enc_field(&h.enc, ep, eend, header_name[k].data(), header_name[k].size(),
                             header_val[k].data(), header_val[k].size());
    }
    if (!ok_hdrs) {
      std::fprintf(stderr, "htgen: the request does not fit one HEADERS frame\n");
      std::exit(1);
    }
    const uint32_t id = h.next_id;
    h.next_id += 2;
    if (latency) c.inflight.emplace_back(id, now_ns());
    // RFC 9113 8.1: content rides in DATA after the HEADERS, so
    // END_STREAM moves to the last DATA frame when there is content.
    const uint8_t hflags =
        body.empty() ? (kH2FlagEndHeaders | kH2FlagEndStream) : kH2FlagEndHeaders;
    // Two encodings that agree mean the encoder's table has settled -
    // everything after this is the same bytes, so they are kept.
    const char* blk = reinterpret_cast<const char*>(buf);
    const size_t blen = static_cast<size_t>(ep - buf);
    if (h.hdr_block.size() == blen && std::memcmp(h.hdr_block.data(), blk, blen) == 0) {
      h.hdr_frozen = true;
    } else {
      h.hdr_block.assign(blk, blen);
    }
    put_frame(c.out, static_cast<uint32_t>(blen), kH2Headers, hflags, id);
    c.out.append(blk, blen);
    if (!body.empty()) {
      put_frame(c.out, static_cast<uint32_t>(body.size()), kH2Data, kH2FlagEndStream, id);
      c.out.append(body.data(), body.size());
    }
    h.open++;
  }

  // As many streams in flight as asked for - h2load's -m, and the reason
  // h2 can beat h1 on the same connection count.
  void h2_fill(uint32_t idx) {
    Conn& c = conns[idx];
    H2Conn& h = *c.h2;
    while (!h.done && h.open < streams) {
      const uint32_t before = h.open;
      h2_request(idx);
      if (h.open == before) break;
    }
    if (!c.out.empty()) queue(idx);
  }

  void h2_stream_done(uint32_t idx, uint32_t id) {
    Conn& c = conns[idx];
    c.h2->open--;
    c.done++;
    responses++;
    if (latency) {
      // Usually the front - streams normally finish in the order they
      // were opened - so the scan is one step, and never longer than
      // the number of streams in flight.
      for (size_t i = 0; i < c.inflight.size(); i++) {
        if (c.inflight[i].first != id) continue;
        lat.add(now_ns() - c.inflight[i].second);
        c.inflight.erase(c.inflight.begin() + static_cast<long>(i));
        break;
      }
    }
    h2_fill(idx);
  }

  // RFC 7541: decode the block whether or not anything here wants it -
  // HPACK is stateful, and a block skipped is a decoder that no longer
  // agrees with the peer about anything. What this end does want is the
  // status, so a server answering 500 fast is not read as throughput.
  void h2_headers(uint32_t idx, const unsigned char* blk, size_t len) {
    Conn& c = conns[idx];
    H2Conn& h = *c.h2;
    const unsigned char* p = blk;
    const unsigned char* const end = blk + len;
    bool ok_status = false;
    // EVERY field decodes into the SAME window. Nothing here outlives the
    // iteration that made it - the status is read and answered on the
    // spot, and every other field is discarded - so walking the buffer
    // forward per field only bought cold cache lines. A five-field block
    // touched 20 KiB across a 64 KiB buffer, per response, for bytes
    // nobody reads twice; now it touches the same few hundred, and they
    // stay hot across millions of them.
    //
    // The decode itself cannot be skipped: HPACK is stateful and a block
    // this end does not decode is a decoder that no longer agrees with
    // the peer about anything.
    while (p < end) {
      lsxpack_header_t xh;
      lsxpack_header_prepare_decode(&xh, h.hdrbuf, 0, kHdrFieldMax);
      if (lshpack_dec_decode(&h.dec, &p, end, &xh) != 0) {
        bad++;
        h.done = true;
        c.dead = true;
        return;
      }
      const char* name = h.hdrbuf + xh.name_offset;
      const char* val = h.hdrbuf + xh.val_offset;
      if (xh.name_len == 7 && std::memcmp(name, ":status", 7) == 0 && xh.val_len == 3) {
        ok_status = val[0] == '2';
      }
    }
    if (!ok_status) bad++;
  }

  // RFC 9113 6.9.1: the connection window shrinks with every DATA byte
  // and only a WINDOW_UPDATE gives it back. Topped up in quarters rather
  // than per frame - one frame in a few thousand carries the update.
  void h2_credit(uint32_t idx, size_t len) {
    Conn& c = conns[idx];
    H2Conn& h = *c.h2;
    h.window_used += static_cast<int64_t>(len);
    if (h.window_used < kWindowTopUp) return;
    put_frame(c.out, 4, kH2WindowUpdate, 0, 0);
    put_u32(c.out, static_cast<uint32_t>(h.window_used));
    h.window_used = 0;
    queue(idx);
  }

  // RFC 9113 4/6: frames in, responses out. Everything a server may send
  // is named - what this end acts on, and what it deliberately ignores.
  //
  // Parses WHERE THE BYTES LIE. Returns how many it consumed; whatever is
  // left is an incomplete frame, and only THAT is carried. The buffer it
  // reads belongs to the kernel's provided ring and is handed back the
  // moment this returns.
  size_t h2_parse(uint32_t idx, const char* base, size_t n) {
    Conn& c = conns[idx];
    H2Conn& h = *c.h2;
    size_t at = 0;
    while (!h.done) {
      const size_t have = n - at;
      if (have < kH2FrameHeaderLen) break;
      const unsigned char* f = reinterpret_cast<const unsigned char*>(base) + at;
      const uint32_t len = h2_u24(f);
      if (len > kH2MaxFrameSize) {
        bad++;
        h.done = true;
        c.dead = true;
        return n;
      }
      if (have < kH2FrameHeaderLen + len) break;
      const uint8_t type = f[3];
      const uint8_t flags = f[4];
      const uint32_t sid = h2_u31(f + 5);
      const unsigned char* body_p = f + kH2FrameHeaderLen;
      size_t blen = len;
      at += kH2FrameHeaderLen + len;
      // RFC 9113 6.1/6.2: padding first, then HEADERS' priority prefix.
      if ((type == kH2Data || type == kH2Headers) && (flags & kH2FlagPadded) != 0) {
        const size_t pad = blen != 0 ? body_p[0] : 0;
        if (blen == 0 || pad + 1 > blen) {
          bad++;
          h.done = true;
          c.dead = true;
          return n;
        }
        body_p += 1;
        blen -= pad + 1;
      }
      if (type == kH2Headers && (flags & kH2FlagPriority) != 0) {
        if (blen < 5) {
          bad++;
          h.done = true;
          c.dead = true;
          return n;
        }
        body_p += 5;
        blen -= 5;
      }

      switch (type) {
        case kH2Settings:
          // RFC 9113 6.5.2 / RFC 7541 4.2: the peer says how large a
          // dynamic table ITS decoder keeps, which is the ceiling for
          // OUR encoder - and a peer that says 0 forbids the table
          // outright, so the kept block would be wrong from then on.
          // Read rather than only acknowledged.
          if ((flags & kH2FlagAck) == 0 && blen % 6 == 0) {
            for (size_t e = 0; e + 6 <= blen; e += 6) {
              const uint16_t key = static_cast<uint16_t>((body_p[e] << 8) | body_p[e + 1]);
              if (key != kH2SettingsHeaderTableSize) continue;
              uint32_t v = 0;
              for (int b = 0; b < 4; b++) v = (v << 8) | body_p[e + 2 + b];
              // Clamped: the number is the peer's, the allocation is
              // ours. Encoding with a smaller table is always legal.
              lshpack_enc_set_max_capacity(&h.enc, v > kEncTableMax ? kEncTableMax : v);
              h.hdr_frozen = false;
              h.hdr_block.clear();
            }
          }
          // RFC 9113 6.5.3: every SETTINGS is acknowledged, and the ack
          // itself is never acknowledged.
          if ((flags & kH2FlagAck) == 0) {
            put_frame(c.out, 0, kH2Settings, kH2FlagAck, 0);
            queue(idx);
          }
          break;
        case kH2Ping:
          // RFC 9113 6.7: the same 8 bytes back, with ACK set.
          if ((flags & kH2FlagAck) == 0 && blen == 8) {
            put_frame(c.out, 8, kH2Ping, kH2FlagAck, 0);
            c.out.append(reinterpret_cast<const char*>(body_p), 8);
            queue(idx);
          }
          break;
        case kH2Headers:
          h.frag_end_stream = (flags & kH2FlagEndStream) != 0;
          if ((flags & kH2FlagEndHeaders) != 0) {
            // The whole block is here, so it is decoded HERE - no copy.
            // frag exists for the split CONTINUATION makes, and this is
            // not one.
            h2_headers(idx, body_p, blen);
            if (h.done) return n;
            if (h.frag_end_stream) h2_stream_done(idx, sid);
          } else {
            h.frag.assign(reinterpret_cast<const char*>(body_p), blen);
          }
          break;
        case kH2Continuation:
          h.frag.append(reinterpret_cast<const char*>(body_p), blen);
          if ((flags & kH2FlagEndHeaders) != 0) {
            h2_headers(idx, reinterpret_cast<const unsigned char*>(h.frag.data()),
                       h.frag.size());
            h.frag.clear();
            if (h.done) return n;
            if (h.frag_end_stream) h2_stream_done(idx, sid);
          }
          break;
        case kH2Data:
          h2_credit(idx, len);
          if ((flags & kH2FlagEndStream) != 0) h2_stream_done(idx, sid);
          break;
        case kH2RstStream:
          // RFC 9113 6.4: the stream is gone; the connection carries on.
          bad++;
          if (h.open != 0) h.open--;
          h2_fill(idx);
          break;
        case kH2Goaway:
          // RFC 9113 6.8: nothing new may be opened on this connection.
          h.done = true;
          break;
        case kH2PushPromise:
          // ENABLE_PUSH is 0 above, so this cannot lawfully arrive - and
          // its header block would desync the decoder if it did.
          bad++;
          h.done = true;
          c.dead = true;
          return n;
        default:
          // RFC 9113 6.3/6.9/4.1: PRIORITY, WINDOW_UPDATE and anything
          // unknown are read past. Nothing here waits on a send window.
          (void)sid;
          break;
      }
    }
    return at;
  }

  // The carry is the ONLY copy this path makes, and only of the bytes
  // that straddle a buffer boundary.
  void h2_feed(uint32_t idx, const char* p, size_t n) {
    Conn& c = conns[idx];
    H2Conn& h = *c.h2;
    if (h.done) return;
    if (h.carry.empty()) {
      const size_t used = h2_parse(idx, p, n);
      if (used < n) h.carry.assign(p + used, n - used);
      return;
    }
    h.carry.append(p, n);
    const size_t used = h2_parse(idx, h.carry.data(), h.carry.size());
    if (used == h.carry.size()) {
      h.carry.clear();
    } else if (used != 0) {
      const size_t rest = h.carry.size() - used;
      std::memmove(h.carry.data(), h.carry.data() + used, rest);
      h.carry.len = rest;
    }
  }

  void feed(uint32_t idx, const char* p, size_t n) {
    if (h2) h2_feed(idx, p, n);
    else h1_feed(idx, p, n);
  }

  void on_recv(uint32_t idx, struct io_uring_cqe* cqe) {
    if (cqe->res <= 0) {
      if (cqe->res == -ENOBUFS) {
        enobufs++;
        arm_recv(idx);
        return;
      }
      return;
    }
    if (!(cqe->flags & IORING_CQE_F_BUFFER)) return;
    rx_bytes += static_cast<uint64_t>(cqe->res);
    uint32_t bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    size_t left = static_cast<size_t>(cqe->res);
    while (left != 0) {
      const size_t take = left < buf_size ? left : buf_size;
      feed(idx, pool + static_cast<size_t>(bid) * buf_size, take);
      left -= take;
      bid = (bid + 1) & (buf_count - 1);
      replenish++;
    }
    if (!(cqe->flags & IORING_CQE_F_MORE)) {
      rearms++;
      arm_recv(idx);
    }
  }
};

int connect_unix(const char* path) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  struct sockaddr_un sa {};
  sa.sun_family = AF_UNIX;
  std::snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
  if (::connect(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) != 0) {
    ::close(fd);
    return -1;
  }
  return fd;
}

int connect_tcp(const char* host, int port) {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  int one = 1;
  ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  struct sockaddr_in sa {};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(static_cast<uint16_t>(port));
  if (::inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
    ::close(fd);
    return -1;
  }
  if (::connect(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) != 0) {
    ::close(fd);
    return -1;
  }
  return fd;
}

}  // namespace

int main(int argc, char** argv) {
  const char* sock = nullptr;
  const char* host = nullptr;
  const char* hdr_host = "localhost";
  const char* path = "/";
  int port = 0;
  int conns = 64;
  int streams = 1;
  int pipeline = 1;
  const char* method = "GET";
  const char* body_arg = nullptr;
  const char* body_file = nullptr;
  bool latency = false;
  int bufs = static_cast<int>(kBufCountDefault);
  int buf_size = static_cast<int>(kBufSizeDefault);
  Span extra_name[32];
  Span extra_val[32];
  size_t nextra = 0;
  bool h2 = false;
  double seconds = 5.0;
  for (int i = 1; i < argc; i++) {
    const auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
    if (std::strcmp(argv[i], "--sock") == 0) sock = next();
    else if (std::strcmp(argv[i], "--host") == 0) host = next();
    else if (std::strcmp(argv[i], "--port") == 0) port = std::atoi(next());
    else if (std::strcmp(argv[i], "--conns") == 0) conns = std::atoi(next());
    else if (std::strcmp(argv[i], "--seconds") == 0) seconds = std::atof(next());
    else if (std::strcmp(argv[i], "--path") == 0) path = next();
    else if (std::strcmp(argv[i], "--host-header") == 0) hdr_host = next();
    else if (std::strcmp(argv[i], "--h2") == 0) h2 = true;
    else if (std::strcmp(argv[i], "--streams") == 0) streams = std::atoi(next());
    else if (std::strcmp(argv[i], "--pipeline") == 0) pipeline = std::atoi(next());
    else if (std::strcmp(argv[i], "--method") == 0) method = next();
    else if (std::strcmp(argv[i], "--body") == 0) body_arg = next();
    else if (std::strcmp(argv[i], "--body-file") == 0) body_file = next();
    else if (std::strcmp(argv[i], "--latency") == 0) latency = true;
    else if (std::strcmp(argv[i], "--bufs") == 0) bufs = std::atoi(next());
    else if (std::strcmp(argv[i], "--buf-size") == 0) buf_size = std::atoi(next());
    else if (std::strcmp(argv[i], "--header") == 0) {
      char* h = const_cast<char*>(next());
      if (h == nullptr) { std::fprintf(stderr, "htgen: --header wants NAME:VALUE\n"); return 2; }
      char* colon = std::strchr(h, ':');
      if (colon == nullptr || colon == h) {
        std::fprintf(stderr, "htgen: --header wants NAME:VALUE, got %s\n", h);
        return 2;
      }
      if (nextra == 32) {
        std::fprintf(stderr, "htgen: at most 32 --header\n");
        return 2;
      }
      // RFC 9113 8.2: h2 field names are lowercase, and ls-hpack indexes
      // the static table by that spelling. Lowercased IN PLACE, in argv,
      // which outlives the run - so the field is never copied anywhere.
      for (char* q = h; q < colon; q++) {
        if (*q >= 'A' && *q <= 'Z') *q = static_cast<char>(*q + 32);
      }
      char* v = colon + 1;
      while (*v == ' ' || *v == '\t') v++;
      extra_name[nextra] = Span(h, static_cast<size_t>(colon - h));
      extra_val[nextra] = Span(v, std::strlen(v));
      nextra++;
    }
    else {
      std::fprintf(stderr, "htgen: unknown argument %s\n", argv[i]);
      return 2;
    }
  }
  if ((sock == nullptr) == (host == nullptr)) {
    std::fprintf(stderr, "htgen: exactly one of --sock PATH or --host H --port P\n");
    return 2;
  }
  if (conns <= 0 || conns > 4096) {
    std::fprintf(stderr, "htgen: --conns must be 1..4096\n");
    return 2;
  }
  if (streams < 1 || streams > 1024) {
    std::fprintf(stderr, "htgen: --streams must be 1..1024\n");
    return 2;
  }
  if (method == nullptr || method[0] == '\0') {
    std::fprintf(stderr, "htgen: --method wants a token (RFC 9110 9)\n");
    return 2;
  }
  if (body_arg != nullptr && body_file != nullptr) {
    std::fprintf(stderr, "htgen: --body and --body-file name the same thing; pick one\n");
    return 2;
  }
  // --body points into argv; --body-file gets ONE buffer, read once,
  // sized from the file and never grown.
  Span body{};
  char* body_mem = nullptr;
  if (body_arg != nullptr) body = Span(body_arg, std::strlen(body_arg));
  if (body_file != nullptr) {
    std::FILE* bf = std::fopen(body_file, "rb");
    if (bf == nullptr) {
      std::fprintf(stderr, "htgen: cannot open %s: %s\n", body_file, std::strerror(errno));
      return 2;
    }
    std::fseek(bf, 0, SEEK_END);
    const long fsz = std::ftell(bf);
    std::fseek(bf, 0, SEEK_SET);
    if (fsz < 0 || fsz > (1 << 20)) {
      std::fprintf(stderr, "htgen: --body-file must be 0..1048576 bytes\n");
      std::fclose(bf);
      return 2;
    }
    body_mem = static_cast<char*>(std::malloc(static_cast<size_t>(fsz) + 1));
    if (body_mem == nullptr) { std::fclose(bf); return 1; }
    const size_t got = std::fread(body_mem, 1, static_cast<size_t>(fsz), bf);
    std::fclose(bf);
    body = Span(body_mem, got);
  }
  // RFC 9113 6.9.2: a stream's initial send window is 65535 and this end
  // never grows it, so content larger than one window would stall
  // mid-body waiting for a WINDOW_UPDATE this client does not yet
  // handle. Refused by name rather than half-sent.
  if (h2 && body.size() > 16384) {
    std::fprintf(stderr,
                 "htgen: --body over 16384 bytes needs h2 flow control this client does "
                 "not do yet (RFC 9113 6.9.2)\n");
    return 2;
  }
  if (latency && pipeline != 1) {
    // wrk's own bug, not repeated here: with a batch on the wire there
    // is ONE timestamp for DEPTH answers, so every percentile it prints
    // is the batch's turnaround divided by nothing.
    std::fprintf(stderr,
                 "htgen: --latency needs --pipeline 1 - a batch has one timestamp for all "
                 "of its answers, and a percentile taken from that is not a latency\n");
    return 2;
  }
  if (bufs < 8 || bufs > (1 << 20) || (bufs & (bufs - 1)) != 0) {
    std::fprintf(stderr, "htgen: --bufs must be a power of two, 8..1048576 - the ring's mask "
                         "is what makes the buffer ids wrap\n");
    return 2;
  }
  if (buf_size < 512 || buf_size > (1 << 20)) {
    std::fprintf(stderr, "htgen: --buf-size must be 512..1048576\n");
    return 2;
  }
  if (pipeline < 1 || pipeline > 1024) {
    std::fprintf(stderr, "htgen: --pipeline must be 1..1024\n");
    return 2;
  }
  if (h2 && pipeline != 1) {
    std::fprintf(stderr, "htgen: --pipeline is h1's (RFC 9112 9.3.2); h2 has --streams\n");
    return 2;
  }
  if (!h2 && streams != 1) {
    std::fprintf(stderr, "htgen: --streams needs --h2 - h1 has one request in flight\n");
    return 2;
  }

  Run run;
  run.h2 = h2;
  run.streams = static_cast<uint32_t>(streams);
  run.path = Span(path, std::strlen(path));
  run.authority = Span(hdr_host, std::strlen(hdr_host));
  run.pipeline = static_cast<uint32_t>(pipeline);
  for (size_t k = 0; k < nextra; k++) {
    run.header_name[k] = extra_name[k];
    run.header_val[k] = extra_val[k];
  }
  run.nheaders = nextra;
  run.method = Span(method, std::strlen(method));
  run.body = body;
  run.latency = latency;
  run.buf_count = static_cast<unsigned>(bufs);
  run.buf_size = static_cast<unsigned>(buf_size);

  // ONE block, carved once, for every per-connection wire buffer. After
  // this line the request path does not touch the allocator again: the
  // sizes are what the SHAPE of the run needs, so a buffer that would
  // overflow is a wrong size here rather than a realloc in the middle
  // of a measurement.
  const size_t one_req = 64 + std::strlen(path) + std::strlen(hdr_host) + body.size() +
                         32 * 256;
  const size_t out_cap = h2 ? (64 + static_cast<size_t>(streams) * (one_req + 32))
                            : (64 + static_cast<size_t>(pipeline) * one_req);
  const size_t carry_cap = kH2MaxFrameSize + kH2FrameHeaderLen;
  const size_t frag_cap = 64 * 1024;
  const size_t hdrbuf_cap = 64 * 1024;
  const size_t blk_cap = 1024;
  const size_t per_conn = 2 * out_cap + (h2 ? carry_cap + frag_cap + hdrbuf_cap + blk_cap
                                            : carry_cap);
  const size_t lat_bytes = latency ? Latency::kBuckets * sizeof(uint64_t) : 0;
  char* block = static_cast<char*>(std::calloc(1, per_conn * static_cast<size_t>(conns) +
                                                  out_cap + lat_bytes));
  if (block == nullptr) {
    std::fprintf(stderr, "htgen: cannot reserve %zu bytes of wire buffers\n",
                 per_conn * static_cast<size_t>(conns));
    return 1;
  }
  char* cursor = block;
  run.request.bind(cursor, out_cap);
  cursor += out_cap;
  if (latency) {
    run.lat.bind(reinterpret_cast<uint64_t*>(cursor));
    cursor += lat_bytes;
  }
  run.request.assign(run.method.data(), run.method.size());
  run.request.append(" ", 1);
  run.request.append(path, std::strlen(path));
  run.request.append(" HTTP/1.1\r\nHost: ", 17);
  run.request.append(hdr_host, std::strlen(hdr_host));
  for (size_t k = 0; k < run.nheaders; k++) {
    run.request.append("\r\n", 2);
    run.request.append(run.header_name[k].data(), run.header_name[k].size());
    run.request.append(": ", 2);
    run.request.append(run.header_val[k].data(), run.header_val[k].size());
  }
  // RFC 9110 8.6: content is announced, always - a request without a
  // Content-Length and without chunked has no content at all, and a
  // server is right to answer 411 or read the next request out of the
  // body. Sent even for an empty --body, because "0" is an answer.
  if (!run.body.empty()) {
    char cl[32];
    const int cln = std::snprintf(cl, sizeof(cl), "\r\nContent-Length: %zu", run.body.size());
    run.request.append(cl, static_cast<size_t>(cln));
  }
  run.request.append("\r\n\r\n", 4);
  if (!run.body.empty()) run.request.append(run.body.data(), run.body.size());
  run.conns.resize(static_cast<size_t>(conns));
  run.fds.resize(static_cast<size_t>(conns));
  for (int i = 0; i < conns; i++) {
    Conn& cc = run.conns[static_cast<size_t>(i)];
    cc.out.bind(cursor, out_cap);   cursor += out_cap;
    cc.wire.bind(cursor, out_cap);  cursor += out_cap;
    if (h2) {
      cc.h2_mem = cursor;
      cursor += carry_cap + frag_cap + hdrbuf_cap + blk_cap;
    } else {
      cc.carry.bind(cursor, carry_cap);
      cursor += carry_cap;
    }
  }
  for (int i = 0; i < conns; i++) {
    const int fd = sock != nullptr ? connect_unix(sock) : connect_tcp(host, port);
    if (fd < 0) {
      std::fprintf(stderr, "htgen: connect %d/%d failed: %s\n", i + 1, conns,
                   std::strerror(errno));
      return 1;
    }
    run.conns[static_cast<size_t>(i)].fd = fd;
    run.fds[static_cast<size_t>(i)] = fd;
  }

  struct io_uring_params p {};
  p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN;
  int rc = io_uring_queue_init_params(kSqEntries, &run.ring, &p);
  if (rc != 0) {
    std::fprintf(stderr, "htgen: queue_init: %s\n", std::strerror(-rc));
    return 1;
  }
  io_uring_register_ring_fd(&run.ring);
  rc = io_uring_register_files(&run.ring, run.fds.data(), static_cast<unsigned>(conns));
  if (rc != 0) {
    std::fprintf(stderr, "htgen: register_files: %s\n", std::strerror(-rc));
    return 1;
  }
  void* mem = ::mmap(nullptr, static_cast<size_t>(run.buf_count) * run.buf_size,
                     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) {
    std::fprintf(stderr, "htgen: mmap pool: %s\n", std::strerror(errno));
    return 1;
  }
  run.pool = static_cast<char*>(mem);
  int bre = 0;
  run.br = io_uring_setup_buf_ring(&run.ring, run.buf_count, kBufGroup, 0, &bre);
  if (run.br == nullptr) {
    std::fprintf(stderr, "htgen: setup_buf_ring: %s\n", std::strerror(-bre));
    return 1;
  }
  const int mask = io_uring_buf_ring_mask(run.buf_count);
  for (uint32_t i = 0; i < run.buf_count; i++) {
    io_uring_buf_ring_add(run.br, run.pool + static_cast<size_t>(i) * run.buf_size,
                          run.buf_size,
                          static_cast<uint16_t>(i), mask, static_cast<int>(i));
  }
  io_uring_buf_ring_advance(run.br, static_cast<int>(run.buf_count));
  // RFC-free, kernel ABI: one recv completion may carry several buffers
  // instead of one. Needs liburing 2.6 and a kernel that answers with the
  // feature bit; built against an older header the whole idea is absent,
  // and the run says so rather than silently costing a syscall per buffer.
#ifdef IORING_FEAT_RECVSEND_BUNDLE
  run.bundles = (run.ring.features & IORING_FEAT_RECVSEND_BUNDLE) != 0;
#else
  run.bundles = false;
  std::fprintf(stderr, "htgen: built against a liburing without send/recv bundles - "
                       "one completion per buffer\n");
#endif
  if (const char* e = std::getenv("HTGEN_BUNDLE")) {
    if (e[0] == '0') run.bundles = false;
  }

  for (int i = 0; i < conns; i++) {
    const uint32_t idx = static_cast<uint32_t>(i);
    run.arm_recv(idx);
    if (h2) {
      run.h2_open(idx);
      run.h2_fill(idx);
    } else {
      // RFC 9112 9.3.2: pipelining is depth requests on the wire at once.
      // The primer puts `pipeline` of them out; each completion below
      // appends exactly one, so the depth holds for the whole run.
      for (uint32_t d = 0; d < run.pipeline; d++) run.conns[idx].out.append(run.request);
    }
    run.conns[idx].queued = false;
    run.arm_send(idx);
  }
  run.to_send.clear();

  const int64_t t0 = now_ns();
  const int64_t deadline = t0 + static_cast<int64_t>(seconds * 1e9);
  for (;;) {
    const int64_t left = deadline - now_ns();
    if (left <= 0) break;
    struct __kernel_timespec ts {left / 1000000000, left % 1000000000};
    struct io_uring_cqe* first = nullptr;
    io_uring_submit_and_wait_timeout(&run.ring, &first, 1, &ts, nullptr);

    unsigned head = 0;
    struct io_uring_cqe* cqe = nullptr;
    unsigned seen = 0;
    io_uring_for_each_cqe(&run.ring, head, cqe) {
      const uint64_t d = io_uring_cqe_get_data64(cqe);
      const uint8_t op = static_cast<uint8_t>(d >> 56);
      const uint32_t idx = static_cast<uint32_t>(d & 0xffffffffu);
      if (op == kOpRecv) run.on_recv(idx, cqe);
      else if (op == kOpSend) run.on_send(idx, cqe);
      seen++;
    }
    io_uring_cq_advance(&run.ring, seen);
    if (run.replenish != 0) {
      io_uring_buf_ring_advance(run.br, static_cast<int>(run.replenish));
      run.replenish = 0;
    }
    for (uint32_t idx : run.to_send) {
      run.conns[idx].queued = false;
      run.arm_send(idx);
    }
    run.to_send.clear();
  }
  const double elapsed = static_cast<double>(now_ns() - t0) / 1e9;

  std::printf(
      "responses=%llu bad=%llu seconds=%.3f rps=%.0f bytes=%llu MB/s=%.2f conns=%d "
      "streams=%d pipeline=%d method=%s proto=%s bundles=%d bufs=%d/%d enobufs=%llu "
      "rearms=%llu tx_bytes=%llu tx_MB/s=%.2f\n",
      static_cast<unsigned long long>(run.responses), static_cast<unsigned long long>(run.bad),
      elapsed, static_cast<double>(run.responses) / elapsed,
      static_cast<unsigned long long>(run.rx_bytes),
      static_cast<double>(run.rx_bytes) / elapsed / (1024.0 * 1024.0), conns, streams, pipeline,
      method, h2 ? "h2" : "h1",
      run.bundles ? 1 : 0, bufs, buf_size,
      static_cast<unsigned long long>(run.enobufs),
      static_cast<unsigned long long>(run.rearms),
      static_cast<unsigned long long>(run.tx_bytes),
      static_cast<double>(run.tx_bytes) / elapsed / (1024.0 * 1024.0));
  if (run.latency) {
    // One line, the same shape as the counts: p50 is where half the
    // answers landed, max is the single worst. A percentile that fell
    // past the histogram's 65 ms says so instead of printing the cap.
    char q50[24], q90[24], q99[24], q999[24];
    const auto spell = [&](double q, char* out) {
      const uint64_t v = run.lat.quantile(q);
      if (v >= Latency::kBuckets) std::snprintf(out, 24, ">65535");
      else std::snprintf(out, 24, "%llu", static_cast<unsigned long long>(v));
    };
    spell(0.50, q50);
    spell(0.90, q90);
    spell(0.99, q99);
    spell(0.999, q999);
    std::printf("latency_us p50=%s p90=%s p99=%s p999=%s max=%llu over65ms=%llu n=%llu\n",
                q50, q90, q99, q999, static_cast<unsigned long long>(run.lat.max_us),
                static_cast<unsigned long long>(run.lat.over),
                static_cast<unsigned long long>(run.lat.n));
  }
  return 0;
}
