# jwtcanary

[简体中文](README.md) | [English](README_EN.md)

> **JWT 验签弱点探针** — 一条命令九发探针：alg=none 直通 / RS256 公钥混淆 / claim 时间边界 / 刷新令牌重放。服务端受理了不该受理的 token，当场现形。零依赖单文件，只读不落地。

[![release](https://img.shields.io/badge/release-v1.0.0-blue)]() [![license](https://img.shields.io/badge/license-MIT-green)]() [![python](https://img.shields.io/badge/python-3.7%2B-informational)]() [![tests](https://img.shields.io/badge/self--tests-29%2F29-green)]()

## 为什么有这个工具

JWT 的安全性几乎全押在「验签」这一行代码上。而验签配置的坑，恰恰是安全通告里的常客：
alg=none 直通、RS256 公钥被当 HMAC 密钥、过期票照收、刷新令牌能重放。
每一类都有真实的大厂网关中过招。

但「你们的 API 有没有这个洞」这个问题，大多数团队没有顺手工具能答。
用 burp 手工打？要造 token、拼请求、判响应，一套下来半天没了。

`jwtcanary` 把「踹一脚门」变成一个可以进 cron 的动作：

```bash
python3 jwtcanary.py --target https://api.example.com/me \
                     --rs256-jwks-url https://sso.example.com/.well-known/jwks.json
echo $?    # 0=防线在 1=有实锤弱点 2=有高度疑似
```

## 它怎么判断（不冤枉好人）

判级只认一条铁律：**服务端明确受理了不该受理的 token，才算弱点**。客户端自己伪造的 token 不算数。

| 判级 | 含义 | 依据 |
|------|------|------|
| **V1** | 实锤弱点 | 网关对「不该受理的 token」返回 2xx 且响应可读为受保护资源 |
| **V2** | 高度疑似 | 弱信号受理（如未知密钥的 HMAC 通过），需人工复核 |
| **I** | 信息级 | 40x 拒绝（正常防线）或其他状态 |
| SKIP | 未执行 | 缺公钥/缺参数/打不到靶——绝不拔高成漏洞 |

四族探针：

1. **none族**：`alg:none`（尾部圆点省略/空签名段两种变体）——历史最经典的 JWT 漏洞
2. **混淆族**：随机密钥 HMAC（疑似没验签）/ RS256 公钥当 HMAC 密钥（经典混淆，支持 `--jwks-file` PEM 或 `--rs256-jwks-url` 自动取 jwks 的 n/e 手工拼 DER，零依赖）/ header.alg 谎报
3. **claim族**：exp 过期 30 天 / nbf 明天才生效 / exp 十年后的「千年票」/ 结构垃圾
4. **刷新族**（`--refresh` 可选）：假刷新令牌兑换 / 同一真令牌重放（探无一次性消费）

## 证据链三件套

每份报告都带：

- **发射台账**：每个测试 token 的 jti（`jwtcanary-` 前缀）、算法、exp——发过什么票可审计
- **线上行为审计**：每个 HTTP 请求的 method/URL/状态码——打过哪里可复盘
- **报告签名**：sha256 报告哈希——报告被事后改动过可发现

## 不变量

- I1 任何请求都不会把真实凭据发往目标以外的主机
- I2 测试 token 的 exp ≤ 600s、jti 固定 `jwtcanary-` 前缀；目标 URL 必须显式给出
- I3 判 V1 必须同时满足：服务端明确受理（2xx 且响应可读为受保护资源）
- I4 打不到靶（超时/404/401 挡在门外）只标 UNREACHABLE/SKIP，绝不拔高成漏洞
- I5 只读：不写系统任何配置，不发修改类请求（全部 GET/POST 探针自身）
- I6 报告必须带 sha256 报告签名与 jti 清单
- I7 密钥材料只在内存：报告与日志永不回显密钥内容

## 快速开始

```bash
# 最小打靶：验证你的 API 会不会收 alg=none / 过期票
python3 jwtcanary.py --target https://api.example.com/me

# 完整版：带 RS256 公钥（混淆探针激活）
python3 jwtcanary.py --target https://api.example.com/me \
                     --rs256-jwks-url https://sso.example.com/.well-known/jwks.json

# 公钥文件形态（PEM）
python3 jwtcanary.py --target https://api.example.com/me --jwks-file ./sso_pub.pem

# 顺带体检刷新令牌（模板里放你的真实 RT，探完建议作废重发）
python3 jwtcanary.py --target https://api.example.com/me \
                     --refresh https://sso.example.com/oauth/token \
                     --refresh-body 'grant_type=refresh_token&client_id=web&refresh_token={rt}'

# 一键安装
curl -fsSL https://gcore.jsdelivr.net/gh/tomlen045/jwtcanary@main/install.sh | sh
```

## 自测与真机验证

```bash
python3 selftest.py    # 29 项：单元不变量 + openssl SPKI 逐字节锚定 + 6 类模拟服务器端到端
```

真机实测（发布前完成）：对 Keycloak 26.3 打靶，10 发全拒判 CLEAN（防线在）；
其中 alg=none 探针得到 HTTP 500 而非干净的 401——防线在，但被踹会摔跤，这本身就是有用的情报。

## 退出码（可接 cron 告警）

| 退出码 | 含义 |
|--------|------|
| 0 | 全拒 / 打不到靶——防线在 |
| 1 | 存在 V1 实锤弱点——今晚就该看 |
| 2 | 存在 V2 高度疑似——安排人工复核 |

## 适用与不适用

**适用**：自家 API/网关的 JWT 验签配置体检、上线前自检、cron 定期巡检、SSO 迁移前后对照。

**不适用**：对无授权的第三方系统打靶（那是违法的）；jwtcanary 只应指向你拥有或获书面授权测试的服务。

## 套件里的位置

哨兵套件的「验签面」：[porteye](https://github.com/tomlen045/porteye) 管「谁在听」，
[suidhunt](https://github.com/tomlen045/suidhunt) 管「谁能提权」，
[authguard](https://github.com/tomlen045/authguard) 管「谁想进来」，
[oidcprobe](https://github.com/tomlen045/oidcprobe) 管「登录服务暴露了什么」，
**jwtcanary 管「递上去的票是不是谁都能伪造」**。

## License

MIT
