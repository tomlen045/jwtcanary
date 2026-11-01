#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jwtcanary — JWT 验签弱点探针 (单文件 / 零依赖 / 只读)

你的 API 网关敢收 `alg:none` 的 JWT 吗？RS256 的公钥文件真被当 HMAC 密钥在用吗？
过期 30 天的 token 还能换来 200 吗？过期 8 小时的刷新令牌还在发新票吗？

jwtcanary 只做五件事：
  1. 签出真实可用的测试 token（HMAC 本地签；RSA 用 cryptography 可选依赖，拒绝则跳过并明确标注）
  2. 打靶：none / 空签名 / HS256 混淆 / 异常 claim 四族探针
  3. 判读：按「token 力量 → 端点回应」的强弱矩阵给 V1(实锤)/V2(高度疑似)/I(信息) 分级
  4. 报告：人话结论 + 建议动作 + 报告哈希签名（报告未被事后改动的凭据）
  5. 退出码即结论：0 全拒（防线在）/ 1 存在 V1 实锤 / 2 存在 V2 高度疑似

不变量：
  I1 任何请求都不会把真实凭据发往目标以外的主机；
  I2 测试 token 的 exp 均 <= 600s、jti 固定带 jwtcanary 前缀，target URL 必须显式给出；
  I3 判 V1 必须同时满足：服务端明确受理（2xx 且响应可读为受保护资源），客户端伪造 token 不算；
  I4 打不到靶（网络错/404/401 挡在门外）只标 UNREACHABLE 或 I 级，绝不拔高成漏洞；
  I5 本工具只读——不写系统任何配置，不发任何修改类 HTTP 方法（全部 GET/POST 探针自身）；
  I6 报告必须带 sha256 报告签名与 jti 清单，便于事后审计到底发过哪些 token；
  I7 密钥材料只在内存：文件读入即用，报告与日志永不回显密钥内容。

用法:
  python3 jwtcanary.py --target https://api.example.com/me --out ./canary-out
  python3 jwtcanary.py --target http://localhost:8080/api/orders --rs256-jwks-url http://localhost:8080/.well-known/jwks.json
  python3 jwtcanary.py --target https://api.example.com/me --jwks-file ./peer.pem.pem   # 公钥文件转 PEM 后喂给混淆探针
  python3 jwtcanary.py --refresh "https://sso.example.com/token" --refresh-body "grant_type=refresh_token&refresh_token=RT"
  python3 jwtcanary.py --target ... --baseline strict   # 已加固站点，校验探针基线（默认）

依赖: 仅 Python 3.8+ 标准库。可选: cryptography (RSA 混淆探针; 未装则该族自动 SKIP)。
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta

__version__ = "1.0.0"
TOOL = "jwtcanary"
UA = "%s/%s (+self-test probe; single-file, zero-dependency)" % (TOOL, __version__)

# ---------------------------------------------------------------- utilities

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def warn(msg: str):
    print("  [warn] %s" % msg, file=sys.stderr)


# --------------------------------------------------------------- HTTP layer

class Http:
    """极薄封装：统一 UA / 超时 / 不跟随重定向到别的主机 / 记录线上行为供审计。"""

    def __init__(self, timeout=8.0, audit=None):
        self.timeout = timeout
        self.audit = audit if audit is not None else []

    def _do(self, method, url, body=None, headers=None):
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("scheme not allowed: %r" % parsed.scheme)
        hdrs = {"User-Agent": UA, "Accept": "*/*"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # 打靶内网自签环境是常态；探针只读、不发敏感数据
        opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
        try:
            with opener.open(req, timeout=self.timeout) as r:
                raw = r.read(65536)
                entry = {"method": method, "url": url, "status": r.status,
                         "server_ct": r.headers.get("Content-Type", "")}
                self.audit.append(entry)
                return r.status, dict(r.headers), raw
        except urllib.error.HTTPError as e:
            raw = e.read(65536)
            self.audit.append({"method": method, "url": url, "status": e.code,
                               "server_ct": e.headers.get("Content-Type", "") if e.headers else ""})
            return e.code, dict(e.headers or {}), raw
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
            self.audit.append({"method": method, "url": url, "status": "CONN_FAIL",
                               "server_ct": "", "err": str(e)[:120]})
            raise

    def get(self, url, headers=None):
        return self._do("GET", url, headers=headers)

    def post(self, url, body=b"", headers=None):
        return self._do("POST", url, body=body, headers=headers)


# ------------------------------------------------------------- token minting

class Mint:
    """测试 token 工厂。I2: exp 短、jti 固定前缀、绝不使用用户真实凭据。"""

    def __init__(self, secret: bytes):
        self.secret = secret
        self.issued = []  # jti 台账 (I6)

    def _claims(self, extra=None, expired=False, future=False, nbf_future=False):
        now = int(time.time())
        jti = "jwtcanary-%s" % secrets.token_hex(6)
        c = {
            "iss": "jwtcanary-probe",
            "sub": "jwtcanary-user",
            "iat": now,
            "jti": jti,
        }
        if expired:
            c["exp"] = now - 86400 * 30      # 过期 30 天
        elif future:
            c["exp"] = now + 86400 * 3650    # 十年后
        else:
            c["exp"] = now + 600             # I2: 最长 10 分钟
        if nbf_future:
            c["nbf"] = now + 86400           # 明天才生效
        if extra:
            c.update(extra)
        self.issued.append({"jti": jti, "alg_hint": None, "exp": c["exp"]})
        return c

    def hs256(self, extra=None, expired=False, future=False, nbf_future=False, key=None):
        c = self._claims(extra, expired, future, nbf_future)
        h = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
        p = b64u(json.dumps(c, separators=(",", ":")).encode())
        signing = ("%s.%s" % (h, p)).encode()
        sig = hmac.new(key if key is not None else self.secret, signing, hashlib.sha256).digest()
        self.issued[-1]["alg_hint"] = "HS256"
        return "%s.%s" % (signing.decode(), b64u(sig))

    def none_alg(self, extra=None, expired=False):
        c = self._claims(extra, expired)
        h = b64u(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
        p = b64u(json.dumps(c, separators=(",", ":")).encode())
        self.issued[-1]["alg_hint"] = "none"
        return "%s.%s." % (h, p)

    def none_alg_empty_sig(self, extra=None):
        c = self._claims(extra)
        h = b64u(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
        p = b64u(json.dumps(c, separators=(",", ":")).encode())
        self.issued[-1]["alg_hint"] = "none-empty-sig"
        return "%s.%s." % (h, p)

    def alg_confusion(self, new_alg: str, extra=None):
        """header 换算法名，签名仍按 HS256 用当前 secret 计算——打「不校验 alg 一致性」的库。"""
        c = self._claims(extra)
        h = b64u(json.dumps({"alg": new_alg, "typ": "JWT"}, separators=(",", ":")).encode())
        p = b64u(json.dumps(c, separators=(",", ":")).encode())
        signing = ("%s.%s" % (h, p)).encode()
        sig = hmac.new(self.secret, signing, hashlib.sha256).digest()
        self.issued[-1]["alg_hint"] = new_alg + "(hs-signed)"
        return "%s.%s" % (signing.decode(), b64u(sig))

    def garbage(self):
        """纯结构垃圾：三段式但 base64 全坏。"""
        self.issued.append({"jti": "jwtcanary-garbage", "alg_hint": "garbage", "exp": 0})
        return "eyJhbGciOiJIUzI1NiJ9.###.###"


def load_secret(path_or_none):
    """密钥材料只在内存 (I7)。未给则随机生成——本地签发验证用，无需持久。"""
    if path_or_none:
        with open(path_or_none, "rb") as f:
            return f.read()
    return secrets.token_bytes(32)


# ------------------------------------------------------------- probe family

P_V1 = "V1"   # 实锤弱点：服务端明确受理了不该受理的 token
P_V2 = "V2"   # 高度疑似：弱信号受理，需人工复核
P_I = "I"     # 信息级：行为正常或无法判读
P_SKIP = "SKIP"


def fetch_jwks_entries(args, http):
    """取混淆探针用的公钥条目，统一形态: [("pem", bytes)] 或 [("jwks", dict)]。
    来源优先级: --jwks-file > --rs256-jwks-url。"""
    if args.jwks_file:
        with open(args.jwks_file, "rb") as f:
            return [("pem", f.read())]
    if args.rs256_jwks_url:
        try:
            st, hd, raw = http.get(args.rs256_jwks_url)
        except Exception:
            return []
        if st != 200:
            return []
        try:
            return [("jwks", json.loads(raw.decode("utf-8", "replace")))]
        except Exception:
            return []
    return []


def probe_family_none(mint, shoot):
    """族 A：alg=none。最强探针。V1 判据: 2xx。"""
    results = []
    variants = [
        ("alg=none 尾点省略", mint.none_alg()),
        ("alg=none 空签名段", mint.none_alg_empty_sig()),
    ]
    for name, tok in variants:
        st, hd, body = shoot(tok)
        verdict = P_I
        note = ""
        if st is None:
            verdict, note = P_SKIP, "UNREACHABLE"
        elif 200 <= st < 300:
            verdict, note = P_V1, "2xx 受理"
        elif st in (401, 403):
            verdict, note = P_I, "40x 拒绝(正常)"
        else:
            verdict, note = P_I, "%d 其他" % st
        results.append({"probe": name, "status": st, "verdict": verdict, "note": note,
                        "resp_sha": sha256_hex(body)[:12] if body else ""})
    return results


def probe_family_confusion(mint, shoot, secret, jwks_entries):
    """族 B：算法混淆。
    B1 HS256-随机密钥:   服务端若拒 → 正常; 若 2xx → V2 (可能根本没验签)
    B2 RS256→HS256 混淆: 需要真实 RS256 公钥 (PEM 文件或 jwks); 2xx → V1 (经典混淆)
    B3 header alg 与签名算法不符: 2xx → V1 (不校验 alg 一致性)
    """
    results = []
    # B1: 正确 HS256 但密钥是随机的（服务端不可能知道）——2xx 只能说明没真验签
    tok = mint.hs256(key=secrets.token_bytes(32))
    st, hd, body = shoot(tok)
    if st is None:
        results.append({"probe": "HS256-随机密钥", "status": None, "verdict": P_SKIP, "note": "UNREACHABLE"})
    elif 200 <= st < 300:
        results.append({"probe": "HS256-随机密钥", "status": st, "verdict": P_V2,
                        "note": "2xx 受理未知密钥签名：疑似未验签或密钥可预测",
                        "resp_sha": sha256_hex(body)[:12] if body else ""})
    else:
        results.append({"probe": "HS256-随机密钥", "status": st, "verdict": P_I,
                        "note": "%d 拒绝(正常)" % st})

    # B2: 公钥当 HMAC 密钥（PEM 文件直用；jwks 取 n/e 手工拼 SPKI PEM，免 cryptography）
    pem_key = None
    for kind, payload in jwks_entries:
        if kind == "pem":
            pem_key = payload if b"BEGIN" in payload else None
            break
        if kind == "jwks":
            for k in payload.get("keys", []):
                if k.get("kty") == "RSA" and k.get("alg") in (None, "RS256") and k.get("n") and k.get("e"):
                    try:
                        der_n = b64u_decode(k["n"])
                        der_e = b64u_decode(k["e"])
                        pem_key = build_rsa_spki_der(der_n, der_e)
                    except Exception:
                        pem_key = None
                    break
            if pem_key:
                break
    if pem_key:
        tok = mint.hs256(key=pem_key)
        st, hd, body = shoot(tok)
        if st is None:
            results.append({"probe": "RS256→HS256 公钥混淆", "status": None,
                            "verdict": P_SKIP, "note": "UNREACHABLE"})
        elif 200 <= st < 300:
            results.append({"probe": "RS256→HS256 公钥混淆", "status": st, "verdict": P_V1,
                            "note": "2xx 受理：服务端把 RS256 公钥当 HMAC 密钥用了",
                            "resp_sha": sha256_hex(body)[:12] if body else ""})
        else:
            results.append({"probe": "RS256→HS256 公钥混淆", "status": st, "verdict": P_I,
                            "note": "%d 拒绝(正常)" % st})
    else:
        results.append({"probe": "RS256→HS256 公钥混淆", "status": None,
                        "verdict": P_SKIP, "note": "未提供 --jwks-file / --rs256-jwks-url 或解析失败"})

    # B3: header 声称 RS256，签名实为 HS256 —— 打不校验 alg 一致性的实现
    tok = mint.alg_confusion("RS256")
    st, hd, body = shoot(tok)
    if st is None:
        results.append({"probe": "header-alg 谎报 RS256", "status": None, "verdict": P_SKIP, "note": "UNREACHABLE"})
    elif 200 <= st < 300:
        results.append({"probe": "header-alg 谎报 RS256", "status": st, "verdict": P_V1,
                        "note": "2xx 受理：签名算法与 header.alg 不一致仍通过",
                        "resp_sha": sha256_hex(body)[:12] if body else ""})
    else:
        results.append({"probe": "header-alg 谎报 RS256", "status": st, "verdict": P_I,
                        "note": "%d 拒绝(正常)" % st})
    return results


def build_rsa_spki_der(n: bytes, e: bytes) -> bytes:
    """手工拼 RSA SPKI DER（免 cryptography 依赖）。n/e 已是无前导零大端整数。"""
    def _int(x: bytes) -> bytes:
        if x[0] & 0x80:
            x = b"\x00" + x
        return b"\x02" + der_len(len(x)) + x

    def der_len(l: int) -> bytes:
        if l < 0x80:
            return bytes([l])
        b = l.to_bytes((l.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(b)]) + b

    rsa_pub = b"\x30" + der_len(len(_int(n) + _int(e))) + _int(n) + _int(e)
    alg = bytes.fromhex("300d06092a864886f70d0101010500")  # rsaEncryption
    spki = b"\x30" + der_len(len(alg + b"\x03" + der_len(len(rsa_pub) + 1) + b"\x00" + rsa_pub)) \
        + alg + b"\x03" + der_len(len(rsa_pub) + 1) + b"\x00" + rsa_pub
    b64 = base64.b64encode(spki).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ("-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n").encode()


def probe_family_claims(mint, shoot):
    """族 C：claim 边界。exp 过期 30 天 / nbf 未来 / exp 十年后 / 结构垃圾。"""
    results = []
    cases = [
        ("exp 过期 30 天", mint.hs256(expired=True), P_V1),
        ("nbf 明天才生效", mint.hs256(nbf_future=True), P_V2),
        ("exp 十年后(千年票)", mint.hs256(future=True), P_V2),
        ("结构垃圾(###)", mint.garbage(), P_V2),
    ]
    for name, tok, sev in cases:
        st, hd, body = shoot(tok)
        if st is None:
            results.append({"probe": name, "status": None, "verdict": P_SKIP, "note": "UNREACHABLE"})
        elif 200 <= st < 300:
            results.append({"probe": name, "status": st, "verdict": sev,
                            "note": "2xx 受理",
                            "resp_sha": sha256_hex(body)[:12] if body else ""})
        elif st in (401, 403):
            results.append({"probe": name, "status": st, "verdict": P_I, "note": "40x 拒绝(正常)"})
        else:
            results.append({"probe": name, "status": st, "verdict": P_I, "note": "%d 其他" % st})
    return results


def probe_refresh_flow(http, url, body_tpl):
    """族 D：刷新令牌边界。假 RT / 空 RT / 重放同一 RT 看是否重复发新票。
    V1: 假 RT 换到 200+token 形态响应; V2: 同一 RT 两次 200 (无一次性消费)。
    body 模板支持 {rt} 占位；没有占位符则就地替换 refresh_token= 的值（探针不改其余字段）。"""
    results = []
    if not url:
        return [{"probe": "刷新令牌边界", "status": None, "verdict": P_SKIP, "note": "未给 --refresh"}]

    def build_body(rt):
        if "{rt}" in body_tpl:
            return body_tpl.replace("{rt}", urllib.parse.quote(rt, safe=""))
        if "refresh_token=" in body_tpl:
            return re.sub(r"refresh_token=[^&]*", "refresh_token=" + urllib.parse.quote(rt, safe=""),
                          body_tpl, count=1)
        sep = "&" if body_tpl else ""
        return body_tpl + sep + "refresh_token=" + urllib.parse.quote(rt, safe="")

    def call(rt):
        hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
        return http.post(url, body=build_body(rt).encode(), headers=hdrs)

    real_rt = extract_rt(body_tpl)
    fake_rt = "jwtcanary-fake-%s" % secrets.token_hex(8)
    st1, hd1, b1 = call(fake_rt)
    if st1 is None:
        results.append({"probe": "假 RT 兑换", "status": None, "verdict": P_SKIP, "note": "UNREACHABLE"})
    elif 200 <= st1 < 300 and looks_like_token_response(b1):
        results.append({"probe": "假 RT 兑换", "status": st1, "verdict": P_V1,
                        "note": "假刷新令牌换到 token 形态响应"})
    else:
        results.append({"probe": "假 RT 兑换", "status": st1, "verdict": P_I,
                        "note": "%d 未受理(正常)" % st1})

    # 重放：若模板里带的是真实 RT（非探针假值），对同一 RT 连打两次看是否重复发新票
    if real_rt and not real_rt.startswith("jwtcanary-fake"):
        st2, _, b2 = call(real_rt)
        st3, _, b3 = call(real_rt)
        if (st2 is not None and st3 is not None
                and 200 <= st2 < 300 and 200 <= st3 < 300
                and looks_like_token_response(b2) and looks_like_token_response(b3)):
            results.append({"probe": "同一 RT 重放", "status": st3, "verdict": P_V2,
                            "note": "同一 RT 两次 200：疑似无一次性消费约束"})
    return results


def extract_rt(body_tpl):
    try:
        q = urllib.parse.parse_qs(body_tpl)
        if "refresh_token" in q:
            return q["refresh_token"][0]
    except Exception:
        pass
    return "jwtcanary-fake-%s" % secrets.token_hex(8)


def looks_like_token_response(body: bytes) -> bool:
    if not body:
        return False
    t = body[:2048].decode("utf-8", "replace").lower()
    return ('"access_token"' in t) or ('"id_token"' in t) or ('bearer' in t and 'token' in t)


# ------------------------------------------------------------------ shooting

def shoot_fn(http, url, hdrname):
    def shoot(token):
        try:
            return http.get(url, headers={hdrname: "Bearer %s" % token})
        except Exception:
            return None, None, b""
    return shoot


# ------------------------------------------------------------------- report

WEAKNESS_ORDER = {"V1": 0, "V2": 1, "I": 2, "SKIP": 3}


def build_report(args, secret_src, families, issued, audit, started):
    worst = "CLEAN"
    if any(r["verdict"] == "V1" for fam in families.values() for r in fam):
        worst = "V1"
    elif any(r["verdict"] == "V2" for fam in families.values() for r in fam):
        worst = "V2"
    elif all(r["verdict"] in ("SKIP",) for fam in families.values() for r in fam):
        worst = "SKIP"

    lines = []
    lines.append("# jwtcanary 报告")
    lines.append("")
    lines.append("- 生成时间: %s" % now_iso())
    lines.append("- 目标: %s" % args.target)
    lines.append("- 工具: jwtcanary v%s (单文件/零依赖/只读)" % __version__)
    lines.append("- 密钥来源: %s" % secret_src)
    lines.append("- 总判: %s" % {"CLEAN": "全拒，防线在", "V1": "存在实锤弱点 (V1)",
                              "V2": "存在高度疑似弱点 (V2)，需人工复核", "SKIP": "全部探针未达靶"}[worst])
    lines.append("")

    advice = {
        "none族": "网关/JWT 库必须显式白名单算法；alg=none 直接 401。禁用「未指定则默认」路径。",
        "混淆族": "验签库的 verify() 必须显式传 algorithms=['RS256']；公钥永远不该进 HMAC 密钥槽。",
        "claim族": "exp/nbf 必须强制校验；库参 verify_exp=True 是默认而不是选项；千年票直接拒。",
        "刷新族": "刷新令牌必须一次性消费+轮换；假 RT 一律 400 invalid_grant 并告警。",
    }
    for fam_name, rows in families.items():
        lines.append("## %s" % fam_name)
        for r in rows:
            mark = {"V1": "[V1]", "V2": "[V2]", "I": "[ I]", "SKIP": "[SKIP]"}[r["verdict"]]
            lines.append("  %s %-22s status=%-4s %s" % (mark, r["probe"], r["status"], r["note"]))
        v1 = [r for r in rows if r["verdict"] == "V1"]
        if v1:
            lines.append("  -> 建议动作: %s" % advice.get(fam_name.split("（")[0].split("(")[0].strip(), "复核 JWT 库验签配置"))
        lines.append("")

    lines.append("## 发射台账 (I6)")
    for it in issued:
        lines.append("  jti=%s alg=%s exp=%s" % (
            it["jti"], it["alg_hint"],
            datetime.fromtimestamp(it["exp"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if it["exp"] else "-"))
    lines.append("")
    lines.append("## 线上行为审计")
    for a in audit:
        lines.append("  %s %s -> %s" % (a.get("method"), a.get("url"), a.get("status")))
    lines.append("")
    lines.append("- 发射 token 数: %d" % len(issued))
    lines.append("- HTTP 请求数: %d (全部 GET/POST 探针自身，无修改类操作)" % len(audit))
    body = "\n".join(lines) + "\n"
    report = {"meta": {"tool": TOOL, "version": __version__, "generated": now_iso(),
                       "target": args.target, "worst": worst},
              "families": families, "issued": issued, "audit": audit, "text": body}
    return worst, report


# --------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(prog=TOOL, description="JWT 验签弱点探针（只读/零依赖）")
    ap.add_argument("--target", required=True, help="受保护资源 URL（GET，带 Bearer 打靶）")
    ap.add_argument("--hdr", default="Authorization", help="携带 token 的 header 名（默认 Authorization）")
    ap.add_argument("--secret-file", help="HMAC 密钥文件（仅本地签发用；不给则随机）")
    ap.add_argument("--jwks-file", help="RS256 公钥 PEM 文件（公钥混淆探针用）")
    ap.add_argument("--rs256-jwks-url", help="目标站 JWKS URL（自动取公钥做混淆探针）")
    ap.add_argument("--refresh", help="OAuth token 端点 URL（刷新令牌边界探针）")
    ap.add_argument("--refresh-body", default="grant_type=refresh_token&refresh_token={rt}",
                    help="刷新请求 body 模板，{rt} 占位")
    ap.add_argument("--out", default="./jwtcanary-out", help="报告输出目录")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--baseline", choices=["strict"], help="以最严口径复核探针基线（自检用）")
    args = ap.parse_args()

    started = now_iso()
    os.makedirs(args.out, exist_ok=True)
    http = Http(timeout=args.timeout)
    secret = load_secret(args.secret_file)
    secret_src = "file:%s" % args.secret_file if args.secret_file else "random(ephemeral)"
    mint = Mint(secret)
    shoot = shoot_fn(http, args.target, args.hdr)

    # 连通性预检（I4: 打不到靶绝不拔高）
    try:
        st0, _, _ = shoot(mint.hs256())
    except Exception:
        st0 = None
    if st0 is None:
        print(json.dumps({"tool": TOOL, "worst": "UNREACHABLE",
                          "hint": "目标不可达，未发射任何判定性探针 (I4)"}, ensure_ascii=False))
        return 0

    jwks_entries = fetch_jwks_entries(args, http)

    families = {}
    families["none族（alg=none 直通车）"] = probe_family_none(mint, shoot)
    families["混淆族（密钥与算法张冠李戴）"] = probe_family_confusion(mint, shoot, secret, jwks_entries)
    families["claim族（时间边界与垃圾）"] = probe_family_claims(mint, shoot)
    if args.refresh:
        families["刷新族（令牌生命周期）"] = probe_refresh_flow(http, args.refresh, args.refresh_body)

    worst, report = build_report(args, secret_src, families, mint.issued, http.audit, started)

    report_path = os.path.join(args.out, "report.json")
    text_path = os.path.join(args.out, "report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)
    report["report_sha256"] = sha256_hex(json.dumps({k: v for k, v in report.items() if k != "report_sha256"},
                                                    ensure_ascii=False, sort_keys=True).encode())
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)
    with open(text_path, "w", encoding="utf-8") as f:
        f.write(report["text"])
    with open(text_path, "a", encoding="utf-8") as f:
        f.write("- 报告签名: sha256:%s\n" % report["report_sha256"])

    print(json.dumps({"tool": TOOL, "worst": worst, "report": os.path.abspath(report_path),
                      "probes": sum(len(v) for v in families.values()),
                      "issued": len(mint.issued), "requests": len(http.audit)}, ensure_ascii=False))
    return {"CLEAN": 0, "V2": 2, "V1": 1}.get(worst, 0)


if __name__ == "__main__":
    sys.exit(main())
