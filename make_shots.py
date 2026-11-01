#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# jwtcanary 文章证据图 x6 (1200x675) — 内容来自真实输出, 密码/密钥已脱敏
from PIL import Image, ImageDraw, ImageFont
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "screenshots")
os.makedirs(OUT, exist_ok=True)
FONT_CJK = "/System/Library/Fonts/STHeiti Medium.ttc"
FONT_MONO = "/System/Library/Fonts/Menlo.ttc"
W, H = 1200, 675
BG, BAR, LINE = "#1b1d23", "#2a2d35", "#0d1117"
GREEN, WHITE, GREY, RED, GOLD, BLUE = "#98c379", "#e6edf3", "#7f8794", "#e06c75", "#e5c07b", "#61afef"

_fc = {}
def F(size, mono):
    key = (size, mono)
    if key not in _fc:
        _fc[key] = ImageFont.truetype(FONT_MONO if mono else FONT_CJK, size)
    return _fc[key]

def has_cjk(t):
    return any('\u2e80' <= ch <= '\u9fff' or ch in '，。：；「」（）｜→·①②③④⑤⑥⑦⑧⑨⑩' for ch in t)

def shot(name, lines, title="dev — zsh"):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 44], fill=BAR)
    d.ellipse([24, 15, 36, 27], fill="#ff5f57"); d.ellipse([44, 15, 56, 27], fill="#febc2e"); d.ellipse([64, 15, 76, 27], fill="#28c840")
    tw = d.textlength(title, font=F(16, False))
    d.text(((W - tw) / 2, 13), title, font=F(16, False), fill="#8b90a0")
    d.rectangle([0, 44, W, 46], fill=LINE)
    y = 74
    for text, color, size, mono in lines:
        if text:
            font = F(size, mono and not has_cjk(text))
            d.text((56, y), text, font=font, fill=color)
        y += int(size * 1.72)
    img.save(os.path.join(OUT, name + ".png"))
    print(name, "OK")

# 1. 一条命令打靶（总览 + 退出码）
shot("jw-shot-1-run", [
    ("$ python3 jwtcanary.py --target https://api.demo.example/me --rs256-jwks-url https://sso.demo.example/certs", WHITE, 20, True),
    ('{"tool":"jwtcanary","worst":"V1","probes":9,"issued":10,"requests":11}', GOLD, 21, True),
    ("$ echo exit=$?", GREY, 21, True),
    ("exit=1                                                    # 1=有实锤弱点 0=防线在 2=疑似", RED, 21, True),
    ("", None, 0, True),
    ("# 9 发探针一轮齐射：none / 混淆 / claim 三族各管一摊", GREY, 21, False),
    ("# 报告落 ./jwtcanary-out/：report.txt 人话版 + report.json 机读版（带 sha256 报告签名）", GREY, 21, False),
])

# 2. V1 报告判读（咬住 alg=none 直通的真实输出，主机脱敏）
shot("jw-shot-2-v1", [
    ("## none族（alg=none 直通车）", WHITE, 22, False),
    ("  [V1] alg=none 尾点省略     status=200  2xx 受理", RED, 21, False),
    ("  [V1] alg=none 空签名段     status=200  2xx 受理", RED, 21, False),
    ("  -> 建议动作: 网关/JWT 库必须显式白名单算法；alg=none 直接 401", GOLD, 20, False),
    ("", None, 0, True),
    ("## 混淆族（密钥与算法张冠李戴）", WHITE, 22, False),
    ("  [ I] HS256-随机密钥        status=401  401 拒绝(正常)", GREEN, 21, False),
    ("  [ I] exp 过期 30 天        status=401  40x 拒绝(正常)", GREEN, 21, False),
    ("", None, 0, True),
    ("# 判级只认一条铁律：服务端明确受理了不该受理的 token 才叫 V1", GREY, 21, False),
])

# 3. 四族探针矩阵（设计图: 同一网关换验签配置, 判级完全不同）
shot("jw-shot-3-matrix", [
    ("alg=none 直通     -> [V1] 实锤：伪造 token 换来 200", RED, 22, False),
    ("随机密钥 HMAC     -> [V2] 疑似：未知密钥签名也放行，多半没验签", GOLD, 22, False),
    ("公钥当 HMAC 密钥  -> [V1] 实锤：RS256→HS256 经典混淆", RED, 22, False),
    ("exp 过期 30 天    -> [V1] 实锤：死票还魂", RED, 22, False),
    ("真票 + 严配网关   -> [CLEAN] 防线在，全部探针 401 拒绝", GREEN, 22, False),
    ("", None, 0, True),
    ("# 打不到靶（超时/404/401 挡在门外）只标 SKIP，绝不拔高成漏洞", GREY, 21, False),
])

# 4. 真机 Keycloak 26.3 全拒 + 500 彩蛋（真实输出, 脱敏）
shot("jw-shot-4-keycloak", [
    ("$ # 拿真票打 userinfo 先证明靶子真受保护: 200 OK", GREY, 20, True),
    ("$ python3 jwtcanary.py --target http://sso.demo.local:8091/.../userinfo --rs256-jwks-url .../certs", WHITE, 19, True),
    ('{"tool":"jwtcanary","worst":"CLEAN","probes":9,"issued":10,"requests":11}', GREEN, 20, True),
    ("  [ I] alg=none 尾点省略      status=500  500 其他", GOLD, 21, False),
    ("  [ I] HS256-随机密钥         status=401  401 拒绝(正常)", GREEN, 21, False),
    ("  [ I] RS256→HS256 公钥混淆   status=401  401 拒绝(正常)", GREEN, 21, False),
    ("  [ I] exp 过期 30 天         status=401  40x 拒绝(正常)", GREEN, 21, False),
    ("", None, 0, True),
    ("# 10 发全拒，防线在；但 alg=none 换来的是 500 不是 401 —— 被踹会摔跤，好过装没事", GREY, 20, False),
])

# 5. 漏洞靶场咬合实拍（故意留洞的模拟网关被一轮咬出两个 V1）
shot("jw-shot-5-range", [
    ("$ # 本地起一个「故意忘配算法白名单」的网关, jwtcanary 一轮打靶:", GREY, 20, False),
    ("$ python3 jwtcanary.py --target http://127.0.0.1:65158/api/orders --jwks-file peer_pub.pem", WHITE, 20, True),
    ('{"worst":"V1","probes":9,"issued":10,"requests":10}   exit=1', GOLD, 21, True),
    ("  [V1] alg=none 尾点省略      status=200", RED, 21, False),
    ("  [V1] alg=none 空签名段      status=200", RED, 21, False),
    ("  [V1] RS256→HS256 公钥混淆   status=200  服务端把公钥当 HMAC 密钥用了", RED, 21, False),
    ("  [ I] exp 过期 30 天         status=401  40x 拒绝(正常)", GREEN, 21, False),
    ("", None, 0, True),
    ("# 一轮齐射同时咬出两个洞：alg=none 直通 + 公钥混淆，附修复建议", GREY, 20, False),
])

# 6. 报告审计三件套（发射台账/线上行为/签名）
shot("jw-shot-6-report", [
    ("## 发射台账 (I6)", WHITE, 22, False),
    ("  jti=jwtcanary-c0409cce428b alg=none    exp=2026-11-01T02:33:02Z", GREY, 20, True),
    ("  jti=jwtcanary-garbage      alg=garbage exp=-", GREY, 20, True),
    ("## 线上行为审计", WHITE, 22, False),
    ("  GET http://127.0.0.1:65158/api/orders -> 401", GREY, 20, True),
    ("  GET http://127.0.0.1:65158/api/orders -> 200", RED, 20, True),
    ("- 发射 token 数: 9 · HTTP 请求数: 9 (全部 GET/POST 探针自身，无修改类操作)", WHITE, 20, False),
    ("- 报告签名: sha256:9f2c4e…", GOLD, 20, True),
    ("", None, 0, True),
    ("# 发过什么票、打过哪个 URL、报告有没有被改过——事后全可审计", GREY, 21, False),
])

print("all shots ->", OUT)
