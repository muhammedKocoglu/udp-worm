# UDPWorm

UDPWorm is a C++20 one-way UDP file transfer tool that uses forward error
correction (FEC) to recover from packet loss and bit-flips. It is built on
Boost.Asio and includes Reed-Solomon (Schifra) and RaptorQ (RFC 6330) FEC
strategies.

## Features

- One-way UDP file transfer with bit-perfect integrity checks.
- Metadata sync: file name, size, permissions, and last modified time.
- FEC strategies via a clean interface:
  - Reed-Solomon (Schifra)
  - RaptorQ (libraptorq)
- Header redundancy: Full Header + two Mini Headers.
- CRC32 on headers and payload to convert bit-flips into erasures.
- Late metadata initialization if the first header is corrupted.
- Loss and bit-flip simulation for sender testing.
- High-precision pacing and larger socket buffers for stable transfer.

## Build

Dependencies:

- CMake 3.16+
- Boost (system)
- OpenSSL (for MD5 logging)
- pthreads

Build commands:

```bash
cmake -S . -B build
cmake --build build
```

The executable is `build/udp_fec_test`.

## Usage

Sender:

```bash
./udp_fec_test sender <filepath> <host> <port> <K> <M> <MTU> <delay_us> <block_delay_us> <loss_rate> <header_flip_rate> <payload_flip_rate> [--fec <rs|raptorq|ldpc>]
```

Receiver:

```bash
./udp_fec_test receiver <port> <K> <M> <timeout_ms> <output_path> [log_path] [--fec <rs|raptorq|ldpc>]
```

Unit tests (no UDP):

```bash
./udp_fec_test unit_test <rs|raptorq> all [symbol_size]
```

Examples:

```bash
./udp_fec_test sender ./test.txt 127.0.0.1 8080 10 4 1400 100 1000 0.05 0.01 0.02 --fec rs
./udp_fec_test receiver 8080 10 4 500 ./out ./recv.log --fec raptorq
./udp_fec_test unit_test rs all 128
./udp_fec_test unit_test raptorq all 128
```

Notes:

- `delay_us` is the pacing delay between packets. For local loopback, use
  at least 50-100 microseconds.
- `block_delay_us` is the pause after each full FEC block (data + parity) is sent.
- Loss and bit-flip rates are floats in [0.0, 1.0].
- Default FEC is Reed-Solomon unless `--fec raptorq` is provided.

## FEC Parameters

K is the number of data symbols per block. M is the number of parity symbols.
For sender/receiver modes, both `K` and `M` are provided explicitly via CLI.

Supported `(K, M)` configurations used by tests and strategy construction:

- `(10, 4)`
- `(50, 20)`
- `(100, 15)`
- `(100, 25)`
- `(100, 40)`

## Protocol Notes

Each packet contains:

1) Full PacketHeader (with CRC32)
2) MiniHeader 1 (with CRC32)
3) MiniHeader 2 (with CRC32)
4) Payload
5) Payload CRC32 (trailer)

If the full header CRC fails, the receiver falls back to the mini headers.
If payload CRC fails, the symbol is dropped as an erasure.

## Project Layout

- `src/` core sender, receiver, and FEC strategies
- `third_party/schifra` Reed-Solomon library
- `third_party/libraptorq` RaptorQ library
