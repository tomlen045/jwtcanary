#!/usr/bin/env python3
# jwtcanary 自检 —— 单元不变量 + openssl SPKI 锚定 + 6 个本地模拟服务器端到端场景
# 铁律：fixture 密钥全部本地生成/显眼合成串；任一 FAIL 立即非零退出
import base64
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "jwtcanary.py")
PY = sys.executable or "python3"

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append((name, detail))
    print(("  [PASS] " if cond else "  [FAIL] ") + name + (("  | " + detail) if (detail and not cond) else ""))


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64pad(s):
    return s + "=" * (-len(s) % 4)


# ---------------------------------------------------------------- load module
from importlib.util import spec_from_file_location, module_from_spec
spec = spec_from_file_location("jwtcanary", TOOL)
jc = module_from_spec(spec)
spec.loader.exec_module(jc)

FIX_SECRET = b"canary-fixture-secret-0123456789abcdef"

# ================================================================ 单元不变量
print("== 单元不变量 ==")
m = jc.Mint(FIX_SECRET)
tok = m.hs256()
pl = json.loads(jc.b64u_decode(tok.split(".")[1]))
check("T01 测试token exp<=600s (I2)", pl["exp"] - pl["iat"] <= 600)
check("T02 jti 固定 jwtcanary 前缀 (I2)", all(i["jti"].startswith("jwtcanary") for i in m.issued))
check("T03 alg=none 签名段为空", m.none_alg().endswith("."))
h4 = json.loads(jc.b64u_decode(m.alg_confusion("RS256").split(".")[0]))
check("T04 alg_confusion header 谎报生效", h4["alg"] == "RS256")
check("T05 garbage 三段但含非法b64", m.garbage().count(".") == 2 and "###" in m.garbage())

# HS256 签名可自验（本地往返）
hh, pp, ss = m.hs256().split(".")
expect = b64u(hmac.new(FIX_SECRET, ("%s.%s" % (hh, pp)).encode(), hashlib.sha256).digest())
check("T06 HS256 签名本地自洽", ss == expect)

m2 = jc.Mint(FIX_SECRET)
tok_exp = m2.hs256(expired=True)
pl_exp = json.loads(jc.b64u_decode(tok_exp.split(".")[1]))
check("T07 expired 标志产出过期票", pl_exp["exp"] < time.time() - 86400 * 29)

check("T08 b64u 往返无损", jc.b64u_decode(jc.b64u("canary-中文-123".encode())).decode("utf-8") == "canary-中文-123")
check("T09 looks_like_token_response", jc.looks_like_token_response(b'{"access_token":"x"}')
      and not jc.looks_like_token_response(b'{"error":"nope"}'))
check("T10 extract_rt 常规模板", jc.extract_rt("grant_type=refresh_token&refresh_token=rt-real-1") == "rt-real-1")

# 报告签名稳定性与篡改敏感性
r1 = {"a": 1}
s1 = jc.sha256_hex(json.dumps(r1, sort_keys=True).encode())
r1["a"] = 2
s2 = jc.sha256_hex(json.dumps(r1, sort_keys=True).encode())
check("T11 报告签名篡改敏感", s1 != s2 and len(s1) == 64)

# 密钥不落盘 (I7)：默认随机密钥来源描述不含路径
check("T12 默认密钥来源为 ephemeral", jc.load_secret(None) != jc.load_secret(None))  # 每次随机

# ================================================================ openssl SPKI 锚定
print("== openssl SPKI 锚定 ==")
tmp = tempfile.mkdtemp(prefix="jwtcanary-selftest-")
try:
    kfile = os.path.join(tmp, "k.pem")
    pfile = os.path.join(tmp, "pub.pem")
    subprocess.run(["openssl", "genrsa", "-out", kfile, "2048"],
                   capture_output=True, check=True, timeout=60)
    subprocess.run(["openssl", "rsa", "-in", kfile, "-pubout", "-out", pfile],
                   capture_output=True, check=True, timeout=60)
    mod = subprocess.run(["openssl", "rsa", "-in", kfile, "-noout", "-modulus"],
                         capture_output=True, text=True, check=True).stdout.strip()
    n_hex = mod.split("=", 1)[1]
    n_bytes = bytes.fromhex(n_hex)
    if n_bytes[0] == 0:
        n_bytes = n_bytes[1:]
    e_bytes = (65537).to_bytes(3, "big")
    mine = jc.build_rsa_spki_der(n_bytes, e_bytes).decode()
    ref = open(pfile).read()
    check("T13 手拼 SPKI DER 与 openssl 公钥逐字节一致",
          mine.split("\n", 1)[1].strip() == ref.strip().split("\n", 1)[1].strip() and "BEGIN PUBLIC KEY" in mine)

    # openssl 独立验证我的 PEM 可被解析
    p2 = os.path.join(tmp, "mine.pem")
    open(p2, "w").write(mine)
    rr = subprocess.run(["openssl", "pkey", "-pubin", "-in", p2, "-noout", "-text"],
                        capture_output=True, text=True)
    check("T14 openssl 能解析手拼 PEM", rr.returncode == 0 and "2048 bit" in rr.stdout)
except FileNotFoundError:
    check("T13 openssl SPKI 锚定", False, "openssl not found")
    raise SystemExit(1)

# ================================================================ 端到端场景
print("== 端到端场景（本地模拟服务器）==")


class Cfg:
    accept_none = False
    accept_any_hmac = False
    confusion_pem = None   # PEM bytes: header.alg 无视，按 HMAC(PEM) 验
    claims_check = True
    rotate_rt = False      # True=刷新令牌一次性（第二次 400）


def judge(cfg, hs_key, tok):
    parts = tok.split(".")
    if len(parts) != 3 or "###" in tok:
        return 401, '{"error":"malformed"}'
    try:
        h = json.loads(base64.urlsafe_b64decode(b64pad(parts[0])))
        p = json.loads(base64.urlsafe_b64decode(b64pad(parts[1])))
    except Exception:
        return 401, '{"error":"malformed"}'
    alg = h.get("alg")
    now = time.time()
    if cfg.claims_check:
        if not p.get("exp") or p["exp"] < now:
            return 401, '{"error":"token expired"}'
        if p.get("nbf") and p["nbf"] > now:
            return 401, '{"error":"token not yet valid"}'
    signing = ("%s.%s" % (parts[0], parts[1])).encode()
    if alg == "none":
        return (200, '{"ok":true,"resource":"orders"}') if cfg.accept_none \
            else (401, '{"error":"alg rejected"}')
    if alg in ("HS256", "RS256") and cfg.confusion_pem is not None:
        # 建模缺陷：根本不看 header.alg，一律把「--jwks-file 的公钥文件」当 HMAC 密钥验
        expect = b64u(hmac.new(cfg.confusion_pem, signing, hashlib.sha256).digest())
        if hmac.compare_digest(sig_of(parts), expect):
            return 200, '{"ok":true,"resource":"orders"}'
        if cfg.accept_any_hmac:
            return 200, '{"ok":true,"resource":"orders"}'
        return 401, '{"error":"alg rejected"}'
    if alg == "HS256":
        expect = b64u(hmac.new(hs_key, signing, hashlib.sha256).digest())
        if hmac.compare_digest(sig_of(parts), expect):
            return 200, '{"ok":true,"resource":"orders"}'
        if cfg.accept_any_hmac:
            return 200, '{"ok":true,"resource":"orders"}'
        return 401, '{"error":"bad signature"}'
    return 401, '{"error":"alg rejected"}'


def sig_of(parts):
    return parts[2] if len(parts) == 3 else ""


def start_server(cfg, hs_key=FIX_SECRET):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            auth = self.headers.get("Authorization", "")
            tok = auth[7:] if auth.startswith("Bearer ") else ""
            code, body = judge(cfg, hs_key, tok)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(ln).decode()
            q = urllib.parse.parse_qs(body)
            rt = q.get("refresh_token", [""])[0]
            if self.path == "/token" and rt == "rt-real-1":
                if cfg.rotate_rt and getattr(H, "_seen_rt", False):
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b'{"error":"invalid_grant"}')
                    return
                H._seen_rt = True
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"access_token":"at-1","token_type":"Bearer"}')
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error":"invalid_grant"}')
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


def run_tool(extra, outname):
    out = os.path.join(tmp, outname)
    cmd = [PY, TOOL, "--out", out, "--timeout", "5"] + extra
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    j = None
    try:
        j = json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:
        pass
    return r.returncode, j, r


port = None
srv = None

# ---- S1 严格服务器 → CLEAN / exit 0
cfg = Cfg()
srv, port = start_server(cfg)
rc, j, r = run_tool(["--target", "http://127.0.0.1:%d/me" % port], "s1")
check("S1 严格站判 CLEAN", j and j.get("worst") == "CLEAN", "got %s" % (j and j.get("worst")))
check("S1 退出码 0", rc == 0, "rc=%d %s" % (rc, r.stdout[-200:]))

# ---- S2 accept_none → V1 / exit 1
cfg2 = Cfg()
cfg2.accept_none = True
srv2, port2 = start_server(cfg2)
rc, j, r = run_tool(["--target", "http://127.0.0.1:%d/me" % port2], "s2")
check("S2 alg=none 直通判 V1", j and j.get("worst") == "V1", "got %s" % (j and j.get("worst")))
check("S2 退出码 1", rc == 1, "rc=%d" % rc)

# ---- S3 accept_any_hmac → V2 / exit 2
cfg3 = Cfg()
cfg3.accept_any_hmac = True
srv3, port3 = start_server(cfg3)
rc, j, r = run_tool(["--target", "http://127.0.0.1:%d/me" % port3], "s3")
check("S3 未验签判 V2", j and j.get("worst") == "V2", "got %s" % (j and j.get("worst")))
check("S3 退出码 2", rc == 2, "rc=%d" % rc)

# ---- S4 PEM 混淆服务器 + --jwks-file → V1 / exit 1
cfg4 = Cfg()
cfg4.confusion_pem = open(pfile, "rb").read()
srv4, port4 = start_server(cfg4)
rc, j, r = run_tool(["--target", "http://127.0.0.1:%d/me" % port4,
                     "--jwks-file", pfile], "s4")
check("S4 公钥混淆判 V1", j and j.get("worst") == "V1", "got %s" % (j and j.get("worst")))
check("S4 退出码 1", rc == 1, "rc=%d" % rc)

# ---- S5 JWKS 路径（n/e 手拼 DER vs 服务器 openssl 公钥）→ V1
jwks = {"keys": [{"kty": "RSA", "alg": "RS256", "kid": "t1",
                  "n": b64u(n_bytes), "e": b64u(e_bytes)}]}
jwks_path = os.path.join(tmp, "jwks.json")
json.dump(jwks, open(jwks_path, "w"))
srv5, port5 = start_server(cfg4)  # 同一混淆后端


class JwksH(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(open(jwks_path, "rb").read())


srvj = ThreadingHTTPServer(("127.0.0.1", 0), JwksH)
threading.Thread(target=srvj.serve_forever, daemon=True).start()
rc, j, r = run_tool(["--target", "http://127.0.0.1:%d/me" % port5,
                     "--rs256-jwks-url", "http://127.0.0.1:%d/jwks.json" % srvj.server_address[1]], "s5")
check("S5 jwks n/e→DER 混淆判 V1 (等价 T13 的功能锚)", j and j.get("worst") == "V1", "got %s" % (j and j.get("worst")))

# ---- S6 刷新族：假 RT 拒 + 真 RT 无轮换重放 → V2
cfg6 = Cfg()
srv6, port6 = start_server(cfg6)
rc, j, r = run_tool(["--target", "http://127.0.0.1:%d/me" % port6,
                     "--refresh", "http://127.0.0.1:%d/token" % port6,
                     "--refresh-body", "grant_type=refresh_token&refresh_token=rt-real-1"], "s6")
rep = json.load(open(os.path.join(tmp, "s6", "report.json")))
fam = rep["families"].get("刷新族（令牌生命周期）", [])
fake_ok = any(p["probe"] == "假 RT 兑换" and p["verdict"] == "I" for p in fam)
replay_ok = any(p["probe"] == "同一 RT 重放" and p["verdict"] == "V2" for p in fam)
check("S6 假 RT 被拒(I) + 真 RT 重放 V2", fake_ok and replay_ok, "fam=%s" % fam)

# ---- S7 UNREACHABLE → worst=UNREACHABLE / exit 0 (I4)
closed = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
closed_port = closed.server_address[1]
closed.server_close()  # 只关 socket 制造拒连；未 serve_forever 的 server 禁用 shutdown()（会死锁）
rc, j, r = run_tool(["--target", "http://127.0.0.1:%d/me" % closed_port], "s7")
check("S7 打不到靶不拔高 (I4)", j and j.get("worst") == "UNREACHABLE" and rc == 0,
      "got %s rc=%d" % (j and j.get("worst"), rc))

# ---- S8 报告完整性：发射台账+审计+签名齐备 (I6/I7)
rep1 = json.load(open(os.path.join(tmp, "s2", "report.json")))
txt = open(os.path.join(tmp, "s2", "report.txt")).read()
check("S8a 报告带发射台账", "发射台账" in rep1["text"] and len(rep1["issued"]) >= 6)
check("S8b 报告带线上审计", len(rep1["audit"]) >= 6)
check("S8c 报告 sha256 签名在", rep1.get("report_sha256") and len(rep1["report_sha256"]) == 64
      and "sha256:" in txt)
check("S8d 报告不回显密钥材料 (I7)", FIX_SECRET.decode() not in json.dumps(rep1))

for s in (srv, srv2, srv3, srv4, srv5, srv6, srvj):
    try:
        s.shutdown()
        s.server_close()
    except Exception:
        pass

shutil.rmtree(tmp, ignore_errors=True)

print("\n== 结果: %d PASS / %d FAIL ==" % (len(PASS), len(FAIL)))
if FAIL:
    for name, detail in FAIL:
        print("  FAIL:", name, detail)
    sys.exit(1)
print("ALL GREEN")
