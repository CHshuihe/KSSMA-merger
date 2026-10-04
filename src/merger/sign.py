# -*- coding: utf-8 -*-
"""v1 签名（JAR 签名）——产出 META-INF/{MANIFEST.MF, CERT.SF, CERT.RSA}。

规范要点（照 JAR Signing / apksigner 的行为）：
    MANIFEST.MF
        Main 节：Manifest-Version / Created-By，后接空行
        每个条目：Name: <路径> \\r\\n SHA-256-Digest: <base64> \\r\\n 空行
        行宽 <= 72 字节，续行以单个空格开头

    CERT.SF
        Main 节：Signature-Version / SHA-256-Digest-Manifest（对 MANIFEST.MF 整体）
        每个条目：Name / SHA-256-Digest（对 MANIFEST.MF 里**该条目那一节**）

    CERT.RSA
        PKCS#7 分离签名（DER），签名对象是 CERT.SF

**为什么逐条目而不是整体**：Android 安装时会校验每个条目的摘要，
这样才能在安装后仍能检测单个文件被篡改。

依赖：cryptography（RSA + X.509）、asn1crypto（PKCS#7 编码）。
"""
import base64
import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding

MANIFEST_NAME = "META-INF/MANIFEST.MF"
SF_NAME = "META-INF/CERT.SF"
RSA_NAME = "META-INF/CERT.RSA"

EXCLUDED_PREFIXES = ("META-INF/",)
MAX_LINE = 72


def _b64_folded(digest_bytes, attr):
    """`attr: <base64>`，按 JAR 规范的 72 字节折行。"""
    b64 = base64.b64encode(digest_bytes).decode("ascii")
    first_len = MAX_LINE - len(attr) - 2          # ": " 占 2 字节
    lines = []
    if len(b64) <= first_len:
        lines.append(b64)
    else:
        lines.append(b64[:first_len])
        rest = b64[first_len:]
        while rest:
            lines.append(" " + rest[:MAX_LINE - 1])
            rest = rest[MAX_LINE - 1:]
    return (attr + ": " + lines[0]).encode("ascii") + b"".join(
        b"\r\n" + l.encode("ascii") for l in lines[1:])


def _name_line(name):
    """`Name: <utf-8>`，长名折行（续行以空格开头）。"""
    nb = name.encode("utf-8")
    if len(b"Name: ") + len(nb) <= MAX_LINE:
        return b"Name: " + nb
    head = nb[:MAX_LINE - len(b"Name: ")]
    rest = nb[MAX_LINE - len(b"Name: "):]
    parts = [b"Name: " + head]
    while rest:
        parts.append(b" " + rest[:MAX_LINE - 1])
        rest = rest[MAX_LINE - 1:]
    return b"\r\n".join(parts)


def build_manifest_sections(entries):
    """entries: [(name, 内容) 或 (name, sha256_digest_bytes)]（按写入顺序）。

    返回 (manifest_bytes, [(name, section_bytes)])，section_bytes **含结尾空行**，
    供 CERT.SF 逐节摘要使用。
    """
    main = b"Manifest-Version: 1.0\r\nCreated-By: KSSMA Merger\r\n\r\n"
    parts = [main]
    sections = []
    for name, content in entries:
        if name.startswith(EXCLUDED_PREFIXES):
            continue
        digest = content if isinstance(content, bytes) and len(content) == 32 \
            else hashlib.sha256(content).digest()
        sec = _name_line(name) + b"\r\n" + _b64_folded(digest, "SHA-256-Digest") + b"\r\n\r\n"
        parts.append(sec)
        sections.append((name, sec))
    return b"".join(parts), sections


def build_sf(manifest_bytes, manifest_sections):
    """CERT.SF：Main 节对整份 MANIFEST.MF 摘要；每节对 MANIFEST.MF 的对应节摘要。"""
    main = (b"Signature-Version: 1.0\r\n"
            b"Created-By: KSSMA Merger\r\n"
            + _b64_folded(hashlib.sha256(manifest_bytes).digest(),
                          "SHA-256-Digest-Manifest")
            + b"\r\n\r\n")
    parts = [main]
    for name, sec in manifest_sections:
        parts.append(_name_line(name) + b"\r\n"
                     + _b64_folded(hashlib.sha256(sec).digest(), "SHA-256-Digest")
                     + b"\r\n\r\n")
    return b"".join(parts)


def _p7_detached(sf_bytes, certs, private_key):
    """PKCS#7 分离签名（DER）——等价 jarsigner 生成的 CERT.RSA。

    certs 是 cryptography 的 x509.Certificate 列表；
    asn1crypto 需要它自己的类型，所以先转 DER 再 load 回来。
    """
    from asn1crypto import algos, cms, core, x509 as a_x509

    cert_objs = []
    for c in certs:
        der = c.public_bytes(Encoding.DER)
        cert_objs.append(cms.CertificateChoices({
            "certificate": a_x509.Certificate.load(der),
        }))

    # 被签名的属性集（content_type + message_digest）
    # 注意：asn1crypto 不导出 SetOfXxx 包装类，直接传 list 让它自行构造
    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({
            "type": "content_type",
            "values": [cms.ContentType("data")],
        }),
        cms.CMSAttribute({
            "type": "message_digest",
            "values": [core.OctetString(hashlib.sha256(sf_bytes).digest())],
        }),
    ])
    # 签名的输入是属性的 DER（外层 tag 由 0xA0 改成 SET 的 0x31）
    der = signed_attrs.dump()
    if der and der[0] == 0xA0:
        der = b"\x31" + der[1:]
    signature = private_key.sign(der, padding.PKCS1v15(), hashes.SHA256())

    # 用第一张证书的 asn1crypto 视图构造 SignerIdentifier
    leaf = cert_objs[0].chosen
    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": leaf.issuer,
                "serial_number": leaf.serial_number,
            })
        }),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": signed_attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm(
            {"algorithm": "rsassa_pkcs1v15"}),
        "signature": signature,
    })

    signed_data = cms.SignedData({
        "version": "v1",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
        # 分离签名：不带内容（只声明 content_type=data）
        "encap_content_info": {"content_type": "data"},
        "certificates": cert_objs,
        "signer_infos": [signer_info],
    })
    return cms.ContentInfo({
        "content_type": "signed_data",
        "content": signed_data,
    }).dump()


def build_meta_inf(entries, private_key, certs):
    """entries: [(name, 内容)]，返回 [(name, bytes)] ×3（顺序：MF, SF, RSA）。"""
    manifest, sections = build_manifest_sections(entries)
    sf = build_sf(manifest, sections)
    p7 = _p7_detached(sf, certs, private_key)
    return [(MANIFEST_NAME, manifest), (SF_NAME, sf), (RSA_NAME, p7)]


# ── 密钥/证书的加载与自生成 ──────────────────────────────

def load_pkcs12(path, password):
    from cryptography.hazmat.primitives.serialization import pkcs12
    with open(path, "rb") as f:
        blob = f.read()
    key, cert, extra = pkcs12.load_key_and_certificates(
        blob, password.encode("utf-8") if password else None)
    if key is None or cert is None:
        raise ValueError("PKCS#12 中缺少私钥或证书: %s" % path)
    return key, [cert] + list(extra or [])


def load_keystore_dir(d, password, create_if_missing=True):
    """从目录加载 `signing.p12`；不存在则生成自签名证书并保存。"""
    path = os.path.join(d, "signing.p12")
    if os.path.isfile(path):
        return load_pkcs12(path, password), path
    if not create_if_missing:
        raise FileNotFoundError(path)
    key, certs = generate_self_signed()
    save_pkcs12(key, certs, path, password)
    return (key, certs), path


def generate_self_signed(common_name="KSSMA Merger", days=10950):
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KSSMA Merger"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    return key, [cert]


def save_pkcs12(key, certs, path, password):
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption, pkcs12)
    blob = pkcs12.serialize_key_and_certificates(
        b"kssma-merger", key, certs[0], certs[1:] or None,
        BestAvailableEncryption(password.encode("utf-8")))
    with open(path, "wb") as f:
        f.write(blob)
