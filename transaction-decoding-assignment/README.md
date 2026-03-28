# Bitcoin Transaction Decoder

## How It Works

### 1. Version (4 bytes, little-endian)
The first 4 bytes give the transaction version. Stored in little-endian, so `02 00 00 00` = version 2.

### 2. SegWit Detection (2 bytes)
After the version, if the next byte is `0x00` (marker) and the byte after is `0x01` (flag), this is a **SegWit transaction** (BIP141). A legacy tx would have a varint input count here, which can never be 0x00 for a valid transaction.

### 3. VarInt Encoding
Bitcoin uses variable-length integers for counts and lengths:
| First byte | Format | Size |
|---|---|---|
| `< 0xFD` | value itself | 1 byte |
| `0xFD` | next 2 bytes (LE) | 3 bytes total |
| `0xFE` | next 4 bytes (LE) | 5 bytes total |
| `0xFF` | next 8 bytes (LE) | 9 bytes total |

### 4. Inputs
Each input contains:
- **Previous TX hash**: 32 bytes, stored in internal byte order (reversed for display)
- **vout**: 4 bytes LE — which output of the previous tx is being spent
- **scriptSig length**: VarInt (0 for native SegWit inputs)
- **scriptSig**: raw bytes (empty for SegWit)
- **sequence**: 4 bytes — used for RBF and locktime signaling

### 5. Outputs
Each output contains:
- **Amount**: 8 bytes LE — value in satoshis (1 BTC = 100,000,000 satoshis)
- **scriptPubKey length**: VarInt
- **scriptPubKey**: locking script defining who can spend this output

### 6. Witness Data (SegWit only)
After all outputs, one witness stack per input is included. Each stack is a list of byte arrays pushed onto the script interpreter stack during validation. For a P2WPKH input this is: `[signature, pubkey]`.

### 7. Locktime (4 bytes, little-endian)
- If < 500,000,000: interpreted as a block height
- If ≥ 500,000,000: interpreted as a Unix timestamp
- This tx has locktime `918,339` — a block height

---

## Transaction Analyzed

| Field | Value |
|---|---|
| Version | 2 |
| Type | SegWit (P2WPKH) |
| Inputs | 1 |
| Outputs | 2 |
| Input txid | `c1368b8e3daedf15612b0185f79f4e82df90f6bcd93714e0e057c355d31c8131` |
| Spending vout | 1 |
| Output #1 | 500,000 sat → P2WPKH |
| Output #2 | 1,050,700 sat → P2WPKH |
| Locktime | 918,339 (block height) |

---

## Script Types Supported

| Pattern | Type |
|---|---|
| `0014<20 bytes>` | P2WPKH — Pay to Witness Public Key Hash |
| `0020<32 bytes>` | P2WSH — Pay to Witness Script Hash |
| `76a914<20 bytes>88ac` | P2PKH — Pay to Public Key Hash (legacy) |
| `a914<20 bytes>87` | P2SH — Pay to Script Hash |
| `5120<32 bytes>` | P2TR — Pay to Taproot |

---

## Key Concepts

- **Little-endian**: most numeric fields are stored least-significant byte first
- **Satoshis**: all amounts are integers in satoshis; divide by 100,000,000 for BTC
- **Witness**: SegWit moves signature data out of the scriptSig into a separate witness field, reducing the tx weight counted toward the block size limit
- **Sequence `0xFFFFFFFD`**: signals RBF (Replace-By-Fee) opt-in — the transaction can be replaced with a higher-fee version while still in the mempool
