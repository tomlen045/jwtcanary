# jwtcanary CHANGELOG

## v1.0.0 (2026-11-01)

首个公开版本。

- 4 探针族 9 发齐射：none族（2变体）/ 混淆族（随机密钥HMAC、RS256→HS256 公钥混淆、header.alg 谎报）/ claim族（过期30天、nbf未来、千年票、结构垃圾）/ 刷新族（假RT、真RT重放）
- V1/V2/I/SKIP 四级判读矩阵：判 V1 必须服务端明确受理（2xx+可读受保护资源），打不到靶绝不拔高（I4）
- RS256 公钥来源双通道：--jwks-file（PEM）或 --rs256-jwks-url（jwks 的 n/e 手工拼 SPKI DER，零依赖，openssl 逐字节锚定）
- 证据链三件套：发射台账（jti/alg/exp）+ 线上行为审计 + sha256 报告签名
- 七条不变量 I1-I7；selftest 29 项全绿（单元 + openssl 锚定 + 6 类模拟服务器端到端）
- 真机实弹：Keycloak 26.3 十发全拒判 CLEAN；本地漏洞靶场一轮咬出双 V1（alg=none 直通 + 公钥混淆）
- 退出码 0/1/2 直连 cron 告警
