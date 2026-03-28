"""
Bitcoin Transaction Hex Decoder
Supports both Legacy and SegWit (BIP141) transactions.
"""

import json
import struct


def decode_transaction(hex_string: str) -> dict:
    """
    Decode a Bitcoin transaction from hex format.

    Args:
        hex_string: Raw transaction hex string

    Returns:
        Dictionary containing all decoded transaction components
    """
    data = bytes.fromhex(hex_string.strip())
    ctx = {"data": data, "pos": 0}

    def read_bytes(n: int) -> bytes:
        result = ctx["data"][ctx["pos"]:ctx["pos"] + n]
        ctx["pos"] += n
        return result

    def read_varint() -> int:
        first = ctx["data"][ctx["pos"]]
        ctx["pos"] += 1
        if first < 0xFD:
            return first
        elif first == 0xFD:
            val = struct.unpack_from("<H", ctx["data"], ctx["pos"])[0]
            ctx["pos"] += 2
        elif first == 0xFE:
            val = struct.unpack_from("<I", ctx["data"], ctx["pos"])[0]
            ctx["pos"] += 4
        else:
            val = struct.unpack_from("<Q", ctx["data"], ctx["pos"])[0]
            ctx["pos"] += 8
        return val

    result = {}

    version_bytes = read_bytes(4)
    result["version"] = struct.unpack("<I", version_bytes)[0]
    result["version_hex"] = version_bytes.hex()

 
    is_segwit = (ctx["data"][ctx["pos"]] == 0x00 and
                 ctx["data"][ctx["pos"] + 1] == 0x01)

    if is_segwit:
        result["marker"] = read_bytes(1).hex()   # "00"
        result["flag"]   = read_bytes(1).hex()   # "01"
    else:
        result["marker"] = None
        result["flag"]   = None


    input_count = read_varint()
    result["input_count"] = input_count
    inputs = []

    for _ in range(input_count):
        prev_hash_raw = read_bytes(32)
        txid = prev_hash_raw[::-1].hex()         

        vout_bytes = read_bytes(4)
        vout = struct.unpack("<I", vout_bytes)[0]

        script_len = read_varint()
        scriptsig  = read_bytes(script_len).hex()

        seq_bytes = read_bytes(4)
        sequence  = seq_bytes.hex()

        inputs.append({
            "txid":           txid,
            "vout":           vout,
            "script_length":  script_len,
            "scriptSig":      scriptsig if scriptsig else "(empty – SegWit input)",
            "sequence":       sequence,
        })

    result["inputs"] = inputs

 
    output_count = read_varint()
    result["output_count"] = output_count
    outputs = []

    for _ in range(output_count):
        amount_bytes = read_bytes(8)
        amount = struct.unpack("<Q", amount_bytes)[0]

        spk_len = read_varint()
        spk     = read_bytes(spk_len).hex()

        outputs.append({
            "amount_satoshis": amount,
            "amount_btc":      round(amount / 1e8, 8),
            "script_length":   spk_len,
            "scriptPubKey":    spk,
            "script_type":     _classify_script(spk),
        })

    result["outputs"] = outputs

   
    if is_segwit:
        witness = []
        for _ in range(input_count):
            stack_items = read_varint()
            stack = []
            for _ in range(stack_items):
                item_len = read_varint()
                item = read_bytes(item_len).hex()
                stack.append(item)
            witness.append(stack)
        result["witness"] = witness
    else:
        result["witness"] = []


    locktime_bytes = read_bytes(4)
    result["locktime"]     = struct.unpack("<I", locktime_bytes)[0]
    result["locktime_hex"] = locktime_bytes.hex()

   
    result["is_segwit"]  = is_segwit
    result["total_bytes"] = len(data)

    return result

def _classify_script(script_hex: str) -> str:
    """Return a human-readable script type label."""
    s = script_hex
    if s.startswith("0014") and len(s) == 44:
        return "P2WPKH (native SegWit v0)"
    if s.startswith("0020") and len(s) == 68:
        return "P2WSH (native SegWit v0)"
    if s.startswith("76a914") and s.endswith("88ac") and len(s) == 50:
        return "P2PKH (legacy)"
    if s.startswith("a914") and s.endswith("87") and len(s) == 46:
        return "P2SH"
    if s.startswith("5120") and len(s) == 68:
        return "P2TR (Taproot)"
    return "unknown"
 
 
# ── Entry point ──────
if __name__ == "__main__":
    tx_hex = (
        "0200000000010131811cd355c357e0e01437d9bcf690df824e9ff785012b6115dfae3d"
        "8e8b36c10100000000fdffffff0220a107000000000016001485d78eb795bd9c8a21af"
        "efc8b6fdaedf718368094c08100000000000160014840ab165c9c2555d4a31b9208ad8"
        "06f89d2535e20247304402207bce86d430b58bb6b79e8c1bbecdf67a530eff3bc61581"
        "a1399e0b28a741c0ee0220303d5ce926c60bf15577f2e407f28a2ef8fe8453abd4048b"
        "716e97dbb1e3a85c01210260828bc77486a55e3bc6032ccbeda915d9494eda17b4a54d"
        "be3b24506d40e4ff43030e00"
    )

    decoded = decode_transaction(tx_hex)
    print(json.dumps(decoded, indent=2))