"""Extract the original signing certificate from a Pairip-protected APK.

Pairip derives the bytecode-decryption key from the runtime APK signature.
To make pairip see the *original* signature even after we re-sign the APK,
the JS hook needs the original cert DER bytes baked into it. This module
pulls those bytes out of the APK Signing Block (V2 / V3) — or, as a
fallback, the legacy V1 PKCS7 block in META-INF/*.RSA / .DSA / .EC.
"""

from ..ANSI_COLORS import ANSI; C = ANSI()
from ..MODULES import IMPORT; M = IMPORT()


# APK Signing Block IDs
ID_V2 = 0x7109871a
ID_V3 = 0xf05368c0
ID_V31 = 0x1b93ad61


def _parse_signing_block(apk_path):
    """Return {block_id: payload_bytes} for the APK Signing Block, or {} if absent."""
    with open(apk_path, 'rb') as f:
        data = f.read()
    import struct

    # Locate End of Central Directory record
    eocd = -1
    for i in range(len(data) - 22, max(-1, len(data) - 65536 - 22), -1):
        if data[i:i+4] == b'PK\x05\x06':
            eocd = i
            break
    if eocd < 0:
        return {}

    cd_off = struct.unpack_from('<I', data, eocd + 16)[0]

    # APK Signing Block (if present) ends with magic "APK Sig Block 42"
    if cd_off < 32 or data[cd_off - 16 : cd_off] != b'APK Sig Block 42':
        return {}

    sb_size_after = struct.unpack_from('<Q', data, cd_off - 24)[0]
    sb_start = cd_off - sb_size_after - 8

    blocks = {}
    pos = sb_start + 8  # skip leading size
    while pos < cd_off - 24:
        pair_len = struct.unpack_from('<Q', data, pos)[0]
        block_id = struct.unpack_from('<I', data, pos + 8)[0]
        blocks[block_id] = data[pos + 12 : pos + 8 + pair_len]
        pos += 8 + pair_len
    return blocks


def _certs_from_scheme_block(block):
    """Each scheme block has length-prefixed signers; each signer's signed_data
    contains the certificate(s)."""
    import struct
    out = []
    pos = 0
    signers_len = struct.unpack_from('<I', block, pos)[0]; pos += 4
    end = pos + signers_len
    while pos < end:
        signer_len = struct.unpack_from('<I', block, pos)[0]; pos += 4
        signer = block[pos : pos + signer_len]; pos += signer_len

        sp = 0
        sd_len = struct.unpack_from('<I', signer, sp)[0]; sp += 4
        sd = signer[sp : sp + sd_len]

        # signed_data: digests | certificates | additional_attributes
        dp = 0
        dgs_len = struct.unpack_from('<I', sd, dp)[0]; dp += 4 + dgs_len
        cs_len  = struct.unpack_from('<I', sd, dp)[0]; dp += 4
        cs_end  = dp + cs_len
        while dp < cs_end:
            c_len = struct.unpack_from('<I', sd, dp)[0]; dp += 4
            out.append(sd[dp : dp + c_len])
            dp += c_len
    return out


def _v1_certs(apk_path):
    """Fallback: parse the first PKCS7 sig block from META-INF/*.RSA|.DSA|.EC."""
    with M.zipfile.ZipFile(apk_path) as z:
        for name in z.namelist():
            up = name.upper()
            if up.startswith('META-INF/') and up.endswith(('.RSA', '.DSA', '.EC')):
                pkcs7 = z.read(name)
                # Walk the DER for the first SEQUENCE that looks like an X.509 cert.
                # Cheap heuristic: find b'\x30\x82' followed by 2-byte big-endian length,
                # then verify the SubjectPublicKeyInfo / Issuer pattern is present.
                # For our purposes we don't need a full ASN.1 parser — openssl will do it.
                import subprocess, tempfile, os, re
                tmp_pem = tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False)
                try:
                    r = subprocess.run(
                        ['openssl', 'pkcs7', '-inform', 'DER', '-in', '/dev/stdin', '-print_certs'],
                        input=pkcs7, capture_output=True, check=False
                    )
                    text = r.stdout.decode('latin-1', errors='replace')
                    pem_certs = re.findall(
                        r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
                        text, re.S
                    )
                    out = []
                    for pem in pem_certs:
                        tmp_pem.seek(0); tmp_pem.truncate()
                        tmp_pem.write(pem); tmp_pem.flush()
                        r2 = subprocess.run(
                            ['openssl', 'x509', '-in', tmp_pem.name, '-outform', 'DER'],
                            capture_output=True, check=False
                        )
                        if r2.stdout:
                            out.append(r2.stdout)
                    return out
                finally:
                    tmp_pem.close()
                    try: os.unlink(tmp_pem.name)
                    except OSError: pass
    return []


def Extract_Original_Cert(apk_path):
    """Return the first signer's certificate DER bytes from `apk_path`.

    Tries V3 → V2 → V1 in that order. Returns None if no signature is found
    (which would mean the APK is unsigned — RKPairip wouldn't be patching it
    in the first place)."""

    blocks = _parse_signing_block(apk_path)

    for sid in (ID_V31, ID_V3, ID_V2):
        if sid in blocks:
            certs = _certs_from_scheme_block(blocks[sid])
            if certs:
                return certs[0]

    v1 = _v1_certs(apk_path)
    if v1:
        return v1[0]

    return None
