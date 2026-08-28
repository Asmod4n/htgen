#ifndef HTGEN_H2_WIRE_HPP
#define HTGEN_H2_WIRE_HPP

// RFC 9113 4/6 and RFC 7541: the h2 wire layer, and nothing above it.
// What a frame IS - the type and flag and error and settings numbers, the
// preface, the nine header bytes, the big-endian reads, and one HPACK
// field encode.
//
// Transcription, not design: every number below is the RFC's. Nothing
// that decides anything lives here - the frame loop, flow control,
// CONTINUATION and the stream lifecycle are htgen.cpp's.
//
// Header-only and free of everything else: no io_uring, no connection
// state. Only <cstddef>/<cstdint> and ls-hpack.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "lshpack.h"

namespace htgen {
enum : uint8_t {
  kH2Data = 0x0,
  kH2Headers = 0x1,
  kH2Priority = 0x2,
  kH2RstStream = 0x3,
  kH2Settings = 0x4,
  kH2PushPromise = 0x5,
  kH2Ping = 0x6,
  kH2Goaway = 0x7,
  kH2WindowUpdate = 0x8,
  kH2Continuation = 0x9,
};

enum : uint8_t {
  kH2FlagEndStream = 0x1,
  kH2FlagAck = 0x1,
  kH2FlagEndHeaders = 0x4,
  kH2FlagPadded = 0x8,
  kH2FlagPriority = 0x20,
};

enum : uint32_t {
  kH2NoError = 0x0,
  kH2ProtocolError = 0x1,
  kH2InternalError = 0x2,
  kH2FlowControlError = 0x3,
  kH2StreamClosed = 0x5,
  kH2FrameSizeError = 0x6,
  kH2RefusedStream = 0x7,
  kH2CompressionError = 0x9,
  kH2EnhanceYourCalm = 0xb,
};

enum : uint16_t {
  kH2SettingsHeaderTableSize = 0x1,
  kH2SettingsEnablePush = 0x2,
  kH2SettingsMaxConcurrentStreams = 0x3,
  kH2SettingsInitialWindowSize = 0x4,
  kH2SettingsMaxFrameSize = 0x5,
};

inline constexpr char kH2Preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
inline constexpr size_t kH2PrefaceLen = 24;
inline constexpr size_t kH2PrefaceAnnounce = 18;

inline constexpr size_t kH2FrameHeaderLen = 9;
inline constexpr uint32_t kH2MaxFrameSize = 16384;
inline constexpr int64_t kH2DefaultWindow = 65535;
inline constexpr uint32_t kH2MaxConcurrentStreams = 256;
inline constexpr int64_t kH2WindowCeiling = 0x7fffffff;

// RFC 9113 4.1: the 9-byte frame header; stream id at offset 5.
inline void h2_put_frame_header(unsigned char* p, uint32_t len, uint8_t type,
                                uint8_t flags, uint32_t stream) {
  p[0] = static_cast<unsigned char>(len >> 16);
  p[1] = static_cast<unsigned char>(len >> 8);
  p[2] = static_cast<unsigned char>(len);
  p[3] = type;
  p[4] = flags;
  p[5] = static_cast<unsigned char>((stream >> 24) & 0x7f);
  p[6] = static_cast<unsigned char>(stream >> 16);
  p[7] = static_cast<unsigned char>(stream >> 8);
  p[8] = static_cast<unsigned char>(stream);
}

// RFC 9113 4.1: the 4 stream-id bytes of an already-emitted frame header.
inline void h2_patch_stream_id(unsigned char* p, uint32_t stream) {
  p[5] = static_cast<unsigned char>((stream >> 24) & 0x7f);
  p[6] = static_cast<unsigned char>(stream >> 16);
  p[7] = static_cast<unsigned char>(stream >> 8);
  p[8] = static_cast<unsigned char>(stream);
}

// RFC 9113 4.1: a frame's length field.
inline uint32_t h2_u24(const unsigned char* p) {
  return (static_cast<uint32_t>(p[0]) << 16) | (static_cast<uint32_t>(p[1]) << 8) | p[2];
}
// RFC 9113 4.1: a 32-bit field, network order.
inline uint32_t h2_u32(const unsigned char* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | p[3];
}
// RFC 9113 4.1: a stream id, reserved bit masked off.
inline uint32_t h2_u31(const unsigned char* p) { return h2_u32(p) & 0x7fffffff; }
// RFC 9113 6.5.1: a settings identifier.
inline uint16_t h2_u16(const unsigned char* p) {
  return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

// RFC 7541 6.2: lane 2 - one per-request field through ls-hpack's
// encoder. ls-hpack wants name and value in ONE buffer with the offsets
// named, so the pair is spelled out here first. Returns false when the
// field would not fit - the caller then has an error to name, not a
// truncated block. Shared: the server encodes its response fields with
// this, the load generator its request pseudo-fields.
inline bool h2_enc_field(struct lshpack_enc* enc, unsigned char*& ep, unsigned char* eend,
                         const char* name, size_t nlen, const char* val, size_t vlen) {
  char hbuf[512];
  if (nlen + 2 + vlen > sizeof(hbuf)) return false;
  std::memcpy(hbuf, name, nlen);
  hbuf[nlen] = ':';
  hbuf[nlen + 1] = ' ';
  std::memcpy(hbuf + nlen + 2, val, vlen);
  lsxpack_header_t xh;
  lsxpack_header_set_offset2(&xh, hbuf, 0, nlen, nlen + 2, vlen);
  unsigned char* np = lshpack_enc_encode(enc, ep, eend, &xh);
  if (np == ep) return false;
  ep = np;
  return true;
}
}  // namespace htgen

#endif  // HTGEN_H2_WIRE_HPP
