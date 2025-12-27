---
title: My thoughts on MongoBleed (CVE-2025-14847)
date: 2025-12-27
categories: [research]
tags: [mongodb, cve, memory-corruption, zlib]
image: /assets/mongobleedd.png
alt: OP_COMPRESSED heap disclosure via zlib inflation mismatch
toc: true
---

# MongoBleed (CVE-2025-14847)

> *A parser-amplified uninitialized heap disclosure in MongoDB’s `OP_COMPRESSED` (zlib) path.*

MongoBleed is a vulnerability in the way that MongoDB processes zlib-compressed wire messages. If you follow the execution path a little further, you will see that it quietly turns a database into a **heap oracle**

MongoDB shipped fixes across all supported branches and published a security bulletin with a **CVSS score of 8.7**.

---

## Introduction

At its core, MongoBleed is a **length-trust bug amplified by a parser**.

MongoDB allocates a heap buffer based on an attacker-controlled **claimed uncompressed size**. zlib inflates fewer bytes than claimed, but MongoDB ends up treating the **entire allocation** as initialized message content. BSON parsing and error handling then reflect bytes from the uninitialized tail back to the client.

but we still need to clarify a thing: unauthenticated here does **not** mean authentication is disabled, it means this code path is reached while decoding `OP_COMPRESSED` at the transport/message layer, **before command dispatch or auth checks**

P.S: I refused to create the cover with the AI. I hope you enjoy my art.
---

## 1. Affected versions

According to MongoDB’s advisory, the following branches are affected prior to these versions:

* **8.2** `< 8.2.3`
* **8.0** `< 8.0.17`
* **7.0** `< 7.0.28`
* **6.0** `< 6.0.27`
* **5.0** `< 5.0.32`
* **4.4** `< 4.4.30`
* legacy **4.2 / 4.0 / 3.6** lines

Release notes for **8.0.17** and **8.2.3** explicitly reference **CVE-2025-14847** and internal ticket **SERVER-115508**.

---

## 2. Low-level anatomy

this issue is best categorised as a **binary protocol parsing failure**, rather than a MongoDB specific logic bug. the vulnerable path is reached while decoding the wire message wrapper.

### 2.1 `MsgHeader` (little-endian)

```c
#pragma pack(push, 1)
typedef struct {
    int32_t messagelength;   
    int32_t requestid;       
    int32_t responseto;
    int32_t opcode;          
} MsgHeader;
#pragma pack(pop)
```
MongoDB has still not yet validated that the claimed decompressed length matches reality

---

### 2.2 `OP_COMPRESSED` layout

```c
#pragma pack(push, 1)
typedef struct {
    MsgHeader header;          
    int32_t originalopcode;    
    int32_t uncompressedsize;  
    uint8_t compressorid;      // zlib == 2
    uint8_t compressed[];      // compressed payload bytes
} OpCompressed;
#pragma pack(pop)
```

the **`uncompressedSize`** field can be controlled by the attacker and becomes the core lever because it directly drives the heap allocation size for the decompression output buffer

---

### 2.3 Minimal parser for Blue Teamer nerds

when you're looking at raw captures or incident traffic, you don't really need a full decoder. you just need enough structure to see whether the compressed header makes sense. That's why i used this small helper to sanity check on **OP_COMPRESSED** frames while looking at captures

```py
import struct

OP_COMPRESSED = 2012

def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]

def parseopcompressed(buf: bytes):
    if len(buf) < 25:
        return None

    msg_len = u32(buf, 0)
    opcode  = u32(buf, 12)

    if opcode != OP_COMPRESSED:
        return None

    if msg_len > len(buf):
        msg_len = len(buf)

    original_opcode = u32(buf, 16)
    claimed_size    = u32(buf, 20)
    compressor_id   = buf[24]

    compressed_len = msg_len - 25
    if compressed_len <= 0:
        return None

    return {
        "msg_len": msg_len,
        "original_opcode": original_opcode,
        "claimed_uncompressed": claimed_size,
        "compressed_len": compressed_len,
        "ratio": claimed_size / compressed_len,
        "compressor": compressor_id,
    }
```

for MongoBleed traffic, `uncompressedSize` is often **orders of magnitude larger** than `compressedLen`. that mismatch *is* the bug.

---

### 2.4 Byte-by-byte view: well-formed vs mismatched `OP_COMPRESSED`

I created a diagram to show how is intentionally **explanatory**, not an operator manual. it shows where the trust boundary breaks

#### Well-formed message

```text
00..03  messageLength        (int32 LE)
04..07  requestID            (int32 LE)
08..0B  responseTo           (int32 LE)
0C..0F  opCode = 2012        (OP_COMPRESSED)

10..13  originalOpcode       (e.g. 2013 = OP_MSG)
14..17  uncompressedSize     (matches reality; excludes MsgHeader)
18      compressorId         (0x02 = zlib)
19..XX  compressed payload   (inflates to exactly uncompressedSize bytes)
```

Logical view after decompression:

```text
[ decompressed OP_MSG payload | EOF ]
```

All bytes consumed by BSON parsing were actually written by zlib.

---

#### Mismatched / vulnerable message

```text
00..03  messageLength        (int32 LE)
04..07  requestID            (int32 LE)
08..0B  responseTo           (int32 LE)
0C..0F  opCode = 2012        (OP_COMPRESSED)

10..13  originalOpcode       (e.g. 2013 = OP_MSG)
14..17  uncompressedSize     (ATTACKER-CLAIMED, very large)
18      compressorId         (0x02 = zlib)
19..1F  compressed payload   (small, valid zlib stream)
```

What zlib actually produces:

```text
[ valid OP_MSG bytes ][ STOP ]
```

What MongoDB *believes* it has:

```text
[ valid OP_MSG bytes ][ UNINITIALIZED HEAP BYTES ][ UNINITIALIZED ... ]
```

BSON parsing then walks into the uninitialized tail.
Many BSON validation errors include the offending field name in the error string, which is how heap fragments end up reflected back to the client.

---

## 3. The zlib side

zlib is not the villain here. it behaves exactly as specified. the mistake lies in how MongoDB code treats lengths:
**allocated capacity** vs **bytes actually written**.

### 3.1 Correct decompression contract

```c
#include <stdint.h>
#include <stddef.h>
#include <zlib.h>

size_t inflate_all(const uint8_t* in, size_t in_len,
                   uint8_t* out, size_t out_cap) {
    z_stream zs = (z_stream){0};
    inflateInit(&zs);

    zs.next_in   = (Bytef*)in;
    zs.avail_in  = (uInt)in_len;
    zs.next_out  = out;
    zs.avail_out = (uInt)out_cap;

    int rc = inflate(&zs, Z_FINISH);
    size_t written = out_cap - zs.avail_out;

    inflateEnd(&zs);

    if (rc != Z_STREAM_END)
        return 0;

    return written;
}
```
this vuln occurs when code effectively substitutes **`out_cap`** for **`written`**, or more generally treats allocation size as “valid decompressed message length”

---

## 4. Why heap bytes leak

this is not an out-of-bounds read.

let's suppose  **N bytes** are allocated and only **k < N** are written, the remaining **N − k** bytes contain allocator leftovers. that is the disclosure primitive, a read of uninitialized memory *within* an allocated buffer.

### 4.1 Why zeroing would have neutered it

```c
uint8_t* out = malloc(uncompressedSize);
memset(out, 0, uncompressedSize);
```

i think this would not fix the length bug, but it would collapse the usefulness of the leak. if the tail is all zeros, fake field names terminate immediately.

MongoDB fixed the **root issue** instead by enforcing real decompressed length and reject mismatches

---

## 5. BSON as an accidental exfiltration channel

the practical leak happens because BSON decoders interpret garbage as structure and then *describe that garbage back to you* in error strings

### 5.1 BSON basics

```text
int32   total_length
byte    element_type
cstring field_name
...     element_value
byte    0x00
```

`cstring` is read until a null byte and uninitialized heap memory often lacks early terminators.

### 5.2 Minimal BSON encoder

```python
import struct

def bson_int32(field, value):
    return b"\x10" + field.encode() + b"\x00" + struct.pack("<i", value)

def bson_doc(elements):
    body = elements + b"\x00"
    return struct.pack("<i", 4 + len(body)) + body
```

---

## 6. Patch analysis

the fix enforces two invariants:

* return the **actual decompressed length**
* reject mismatched size claims

in practice, patched builds stop treating “allocated output size” as “valid decompressed message length” and error out on inconsistent compressed headers.

so, verify your version!

---

## 7. Heap object taxonomy inside `mongod`

**Network layer**

* receive buffers
* message wrappers
* decompression buffers

**BSON machinery**

* backing buffers
* parse cursors
* error formatting paths

**Storage glue**

* configuration strings
* diagnostics text
* session metadata

---

## 8. Remediation

### Patch

Upgrade to fixed versions (≥ **8.0.17** / **8.2.3**).

### Reduce exposure

* never expose MongoDB to the internet
* restrict via private networking
* consider mTLS or client certificates

---
