// htgen: an HTTP load generator on io_uring, one ring and one thread.
//
// wrk costs about three times as much CPU per request as a ring server
// spends answering it, so on a fast host a benchmark stops measuring the
// server and starts measuring wrk - and raising its thread count only
// moves the wall. This does the same thing a ring server does, with the
// roles swapped: connect instead of accept, multishot recv out of a
// provided buffer ring, send bundles where the kernel offers them, one
// ring enter carrying hundreds of completions.
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
// Prints one line of counts. h2load and wrk stay the ORACLES: a number
// from here means nothing until one of them says roughly the same thing
// on the same box.
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
#include <string>
#include <vector>

#include "liburing.h"

extern "C" {
#include "picohttpparser.h"
}

#include "h2_wire.hpp"

namespace {

using namespace htgen;

// The reactor's own geometry, so the two ends are priced the same way.
constexpr unsigned kBufCount = 2048;
constexpr unsigned kBufSize = 4096;
constexpr unsigned kBufGroup = 1;
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
void put_frame(std::string& out, uint32_t len, uint8_t type, uint8_t flags, uint32_t stream) {
  unsigned char fh[kH2FrameHeaderLen];
  h2_put_frame_header(fh, len, type, flags, stream);
  out.append(reinterpret_cast<const char*>(fh), sizeof(fh));
}

void put_u32(std::string& out, uint32_t v) {
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
  std::string in;          // frames as they arrive, reassembled
  size_t in_at = 0;        // how much of `in` is already consumed
  std::string frag;        // RFC 9113 6.10: a block across CONTINUATIONs
  bool frag_end_stream = false;
  std::vector<char> hdrbuf;
  uint32_t next_id = 1;
  uint32_t open = 0;       // streams in flight
  int64_t window_used = 0; // DATA counted against the connection window
  bool done = false;       // GOAWAY seen, or the connection broke

  H2Conn() {
    lshpack_enc_init(&enc);
    lshpack_dec_init(&dec);
    hdrbuf.resize(8192);
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
struct Conn {
  int fd = -1;
  size_t body_left = 0;   // RFC 9110 8.6: content still to arrive
  bool in_body = false;
  std::string carry;      // only used when a HEAD spans two buffers
  uint64_t done = 0;
  std::string out;        // queued for the wire, nothing in flight yet
  std::string wire;       // what the send in flight is reading from
  size_t sent_at = 0;     // how much of `wire` the kernel has taken
  bool sending = false;
  bool queued = false;    // already in Load::to_send this round
  bool dead = false;
  std::unique_ptr<H2Conn> h2;
};

struct Load {
  struct io_uring ring {};
  struct io_uring_buf_ring* br = nullptr;
  char* pool = nullptr;
  std::vector<Conn> conns;
  std::vector<int> fds;
  std::string request;    // h1: the constant line; h2: unused
  std::string path;
  std::string authority;
  bool h2 = false;
  uint32_t streams = 1;
  bool bundles = false;
  unsigned replenish = 0;
  uint64_t responses = 0;
  uint64_t bad = 0;
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
  void h1_feed(uint32_t idx, const char* p, size_t n) {
    Conn& c = conns[idx];
    while (n != 0) {
      if (c.in_body) {
        const size_t take = n < c.body_left ? n : c.body_left;
        c.body_left -= take;
        p += take;
        n -= take;
        if (c.body_left == 0) {
          c.in_body = false;
          h1_complete(idx);
        }
        continue;
      }
      const char* head = p;
      size_t head_len = n;
      if (!c.carry.empty()) {
        c.carry.append(p, n);
        head = c.carry.data();
        head_len = c.carry.size();
      }
      int minor = 0, status = 0;
      const char* msg = nullptr;
      size_t msg_len = 0;
      struct phr_header hdr[64];
      size_t nhdr = sizeof(hdr) / sizeof(hdr[0]);
      const int r = phr_parse_response(head, head_len, &minor, &status, &msg, &msg_len, hdr,
                                       &nhdr, 0);
      if (r == -2) {
        if (c.carry.empty()) c.carry.assign(p, n);
        return;
      }
      if (r < 0) {
        bad++;
        c.carry.clear();
        return;
      }
      size_t clen = 0;
      for (size_t i = 0; i < nhdr; i++) {
        if (hdr[i].name_len == 14 && strncasecmp(hdr[i].name, "Content-Length", 14) == 0) {
          clen = static_cast<size_t>(std::strtoull(std::string(hdr[i].value, hdr[i].value_len)
                                                       .c_str(),
                                                   nullptr, 10));
        }
      }
      const size_t consumed = static_cast<size_t>(r);
      const size_t rest = head_len - consumed;
      c.in_body = true;
      c.body_left = clen;
      if (!c.carry.empty()) {
        // The carry held the split head; what follows it is the content.
        std::string tail(head + consumed, rest);
        c.carry.clear();
        if (!tail.empty()) h1_feed(idx, tail.data(), tail.size());
        else if (clen == 0) {
          c.in_body = false;
          h1_complete(idx);
        }
        return;
      }
      p += consumed;
      n -= consumed;
      if (clen == 0) {
        c.in_body = false;
        h1_complete(idx);
      }
    }
  }

  void h1_complete(uint32_t idx) {
    Conn& c = conns[idx];
    c.done++;
    responses++;
    c.out.append(request);
    queue(idx);
  }

  // RFC 9113 3.4: the client's half of the preface, then the two windows
  // opened wide - SETTINGS for every stream to come, one WINDOW_UPDATE
  // for the connection, whose 65535 is not settable any other way.
  void h2_open(uint32_t idx) {
    Conn& c = conns[idx];
    c.h2 = std::make_unique<H2Conn>();
    c.out.append(kH2Preface, kH2PrefaceLen);
    std::string s;
    s.push_back(0);
    s.push_back(static_cast<char>(kH2SettingsEnablePush));
    put_u32(s, 0);
    s.push_back(0);
    s.push_back(static_cast<char>(kH2SettingsInitialWindowSize));
    put_u32(s, static_cast<uint32_t>(kH2WindowCeiling));
    put_frame(c.out, static_cast<uint32_t>(s.size()), kH2Settings, 0, 0);
    c.out.append(s);
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
    unsigned char buf[1024];
    unsigned char* ep = buf;
    unsigned char* const eend = buf + sizeof(buf);
    const bool ok =
        h2_enc_field(&h.enc, ep, eend, ":method", 7, "GET", 3) &&
        h2_enc_field(&h.enc, ep, eend, ":scheme", 7, "http", 4) &&
        h2_enc_field(&h.enc, ep, eend, ":authority", 10, authority.data(), authority.size()) &&
        h2_enc_field(&h.enc, ep, eend, ":path", 5, path.data(), path.size());
    if (!ok) {
      std::fprintf(stderr, "htgen: the request does not fit one HEADERS frame\n");
      std::exit(1);
    }
    const uint32_t id = h.next_id;
    h.next_id += 2;
    put_frame(c.out, static_cast<uint32_t>(ep - buf), kH2Headers,
              kH2FlagEndHeaders | kH2FlagEndStream, id);
    c.out.append(reinterpret_cast<const char*>(buf), static_cast<size_t>(ep - buf));
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

  void h2_stream_done(uint32_t idx) {
    Conn& c = conns[idx];
    c.h2->open--;
    c.done++;
    responses++;
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
    size_t used = 0;
    bool ok_status = false;
    while (p < end) {
      if (h.hdrbuf.size() < used + 4096) h.hdrbuf.resize(used + 4096);
      lsxpack_header_t xh;
      lsxpack_header_prepare_decode(&xh, &h.hdrbuf[used], 0, 4096);
      if (lshpack_dec_decode(&h.dec, &p, end, &xh) != 0) {
        bad++;
        h.done = true;
        c.dead = true;
        return;
      }
      const char* name = &h.hdrbuf[used] + xh.name_offset;
      const char* val = &h.hdrbuf[used] + xh.val_offset;
      if (xh.name_len == 7 && std::memcmp(name, ":status", 7) == 0 && xh.val_len == 3) {
        ok_status = val[0] == '2';
      }
      used += xh.val_offset + xh.val_len;
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
  void h2_feed(uint32_t idx, const char* p, size_t n) {
    Conn& c = conns[idx];
    H2Conn& h = *c.h2;
    if (h.done) return;
    h.in.append(p, n);
    for (;;) {
      const size_t have = h.in.size() - h.in_at;
      if (have < kH2FrameHeaderLen) break;
      const unsigned char* f =
          reinterpret_cast<const unsigned char*>(h.in.data()) + h.in_at;
      const uint32_t len = h2_u24(f);
      if (len > kH2MaxFrameSize) {
        bad++;
        h.done = true;
        c.dead = true;
        return;
      }
      if (have < kH2FrameHeaderLen + len) break;
      const uint8_t type = f[3];
      const uint8_t flags = f[4];
      const uint32_t sid = h2_u31(f + 5);
      const unsigned char* body = f + kH2FrameHeaderLen;
      size_t blen = len;
      // RFC 9113 6.1/6.2: padding first, then HEADERS' priority prefix.
      if ((type == kH2Data || type == kH2Headers) && (flags & kH2FlagPadded) != 0) {
        const size_t pad = blen != 0 ? body[0] : 0;
        if (blen == 0 || pad + 1 > blen) {
          bad++;
          h.done = true;
          c.dead = true;
          return;
        }
        body += 1;
        blen -= pad + 1;
      }
      if (type == kH2Headers && (flags & kH2FlagPriority) != 0) {
        if (blen < 5) {
          bad++;
          h.done = true;
          c.dead = true;
          return;
        }
        body += 5;
        blen -= 5;
      }
      h.in_at += kH2FrameHeaderLen + len;

      switch (type) {
        case kH2Settings:
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
            c.out.append(reinterpret_cast<const char*>(body), 8);
            queue(idx);
          }
          break;
        case kH2Headers:
          h.frag.assign(reinterpret_cast<const char*>(body), blen);
          h.frag_end_stream = (flags & kH2FlagEndStream) != 0;
          if ((flags & kH2FlagEndHeaders) != 0) {
            h2_headers(idx, reinterpret_cast<const unsigned char*>(h.frag.data()),
                       h.frag.size());
            h.frag.clear();
            if (h.done) return;
            if (h.frag_end_stream) h2_stream_done(idx);
          }
          break;
        case kH2Continuation:
          h.frag.append(reinterpret_cast<const char*>(body), blen);
          if ((flags & kH2FlagEndHeaders) != 0) {
            h2_headers(idx, reinterpret_cast<const unsigned char*>(h.frag.data()),
                       h.frag.size());
            h.frag.clear();
            if (h.done) return;
            if (h.frag_end_stream) h2_stream_done(idx);
          }
          break;
        case kH2Data:
          h2_credit(idx, len);
          if ((flags & kH2FlagEndStream) != 0) h2_stream_done(idx);
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
          return;
        default:
          // RFC 9113 6.3/6.9/4.1: PRIORITY, WINDOW_UPDATE and anything
          // unknown are read past. Nothing here waits on a send window.
          (void)sid;
          break;
      }
      // Consumed frames are dropped in one move, not one erase per frame.
      if (h.in_at > 8192) {
        h.in.erase(0, h.in_at);
        h.in_at = 0;
      }
    }
    if (h.in_at != 0 && h.in_at == h.in.size()) {
      h.in.clear();
      h.in_at = 0;
    }
  }

  void feed(uint32_t idx, const char* p, size_t n) {
    if (h2) h2_feed(idx, p, n);
    else h1_feed(idx, p, n);
  }

  void on_recv(uint32_t idx, struct io_uring_cqe* cqe) {
    if (cqe->res <= 0) {
      if (cqe->res == -ENOBUFS) {
        arm_recv(idx);
        return;
      }
      return;
    }
    if (!(cqe->flags & IORING_CQE_F_BUFFER)) return;
    uint32_t bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    size_t left = static_cast<size_t>(cqe->res);
    while (left != 0) {
      const size_t take = left < kBufSize ? left : kBufSize;
      feed(idx, pool + static_cast<size_t>(bid) * kBufSize, take);
      left -= take;
      bid = (bid + 1) & (kBufCount - 1);
      replenish++;
    }
    if (!(cqe->flags & IORING_CQE_F_MORE)) arm_recv(idx);
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
  if (!h2 && streams != 1) {
    std::fprintf(stderr, "htgen: --streams needs --h2 - h1 has one request in flight\n");
    return 2;
  }

  Load L;
  L.h2 = h2;
  L.streams = static_cast<uint32_t>(streams);
  L.path = path;
  L.authority = hdr_host;
  L.request.assign("GET ").append(path).append(" HTTP/1.1\r\nHost: ").append(hdr_host).append(
      "\r\n\r\n");
  L.conns.resize(static_cast<size_t>(conns));
  L.fds.resize(static_cast<size_t>(conns));
  for (int i = 0; i < conns; i++) {
    const int fd = sock != nullptr ? connect_unix(sock) : connect_tcp(host, port);
    if (fd < 0) {
      std::fprintf(stderr, "htgen: connect %d/%d failed: %s\n", i + 1, conns,
                   std::strerror(errno));
      return 1;
    }
    L.conns[static_cast<size_t>(i)].fd = fd;
    L.fds[static_cast<size_t>(i)] = fd;
  }

  struct io_uring_params p {};
  p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN;
  int rc = io_uring_queue_init_params(kSqEntries, &L.ring, &p);
  if (rc != 0) {
    std::fprintf(stderr, "htgen: queue_init: %s\n", std::strerror(-rc));
    return 1;
  }
  io_uring_register_ring_fd(&L.ring);
  rc = io_uring_register_files(&L.ring, L.fds.data(), static_cast<unsigned>(conns));
  if (rc != 0) {
    std::fprintf(stderr, "htgen: register_files: %s\n", std::strerror(-rc));
    return 1;
  }
  void* mem = ::mmap(nullptr, static_cast<size_t>(kBufCount) * kBufSize,
                     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) {
    std::fprintf(stderr, "htgen: mmap pool: %s\n", std::strerror(errno));
    return 1;
  }
  L.pool = static_cast<char*>(mem);
  int bre = 0;
  L.br = io_uring_setup_buf_ring(&L.ring, kBufCount, kBufGroup, 0, &bre);
  if (L.br == nullptr) {
    std::fprintf(stderr, "htgen: setup_buf_ring: %s\n", std::strerror(-bre));
    return 1;
  }
  const int mask = io_uring_buf_ring_mask(kBufCount);
  for (uint32_t i = 0; i < kBufCount; i++) {
    io_uring_buf_ring_add(L.br, L.pool + static_cast<size_t>(i) * kBufSize, kBufSize,
                          static_cast<uint16_t>(i), mask, static_cast<int>(i));
  }
  io_uring_buf_ring_advance(L.br, kBufCount);
  // RFC-free, kernel ABI: one recv completion may carry several buffers
  // instead of one. Needs liburing 2.6 and a kernel that answers with the
  // feature bit; built against an older header the whole idea is absent,
  // and the run says so rather than silently costing a syscall per buffer.
#ifdef IORING_FEAT_RECVSEND_BUNDLE
  L.bundles = (L.ring.features & IORING_FEAT_RECVSEND_BUNDLE) != 0;
#else
  L.bundles = false;
  std::fprintf(stderr, "htgen: built against a liburing without send/recv bundles - "
                       "one completion per buffer\n");
#endif
  if (const char* e = std::getenv("HTGEN_BUNDLE")) {
    if (e[0] == '0') L.bundles = false;
  }

  for (int i = 0; i < conns; i++) {
    const uint32_t idx = static_cast<uint32_t>(i);
    L.arm_recv(idx);
    if (h2) {
      L.h2_open(idx);
      L.h2_fill(idx);
    } else {
      L.conns[idx].out.append(L.request);
    }
    L.conns[idx].queued = false;
    L.arm_send(idx);
  }
  L.to_send.clear();

  const int64_t t0 = now_ns();
  const int64_t deadline = t0 + static_cast<int64_t>(seconds * 1e9);
  for (;;) {
    const int64_t left = deadline - now_ns();
    if (left <= 0) break;
    struct __kernel_timespec ts {left / 1000000000, left % 1000000000};
    struct io_uring_cqe* first = nullptr;
    io_uring_submit_and_wait_timeout(&L.ring, &first, 1, &ts, nullptr);

    unsigned head = 0;
    struct io_uring_cqe* cqe = nullptr;
    unsigned seen = 0;
    io_uring_for_each_cqe(&L.ring, head, cqe) {
      const uint64_t d = io_uring_cqe_get_data64(cqe);
      const uint8_t op = static_cast<uint8_t>(d >> 56);
      const uint32_t idx = static_cast<uint32_t>(d & 0xffffffffu);
      if (op == kOpRecv) L.on_recv(idx, cqe);
      else if (op == kOpSend) L.on_send(idx, cqe);
      seen++;
    }
    io_uring_cq_advance(&L.ring, seen);
    if (L.replenish != 0) {
      io_uring_buf_ring_advance(L.br, static_cast<int>(L.replenish));
      L.replenish = 0;
    }
    for (uint32_t idx : L.to_send) {
      L.conns[idx].queued = false;
      L.arm_send(idx);
    }
    L.to_send.clear();
  }
  const double elapsed = static_cast<double>(now_ns() - t0) / 1e9;

  std::printf(
      "responses=%llu bad=%llu seconds=%.3f rps=%.0f conns=%d streams=%d proto=%s bundles=%d\n",
      static_cast<unsigned long long>(L.responses), static_cast<unsigned long long>(L.bad),
      elapsed, static_cast<double>(L.responses) / elapsed, conns, streams, h2 ? "h2" : "h1",
      L.bundles ? 1 : 0);
  return 0;
}
