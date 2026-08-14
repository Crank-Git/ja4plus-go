# FoxIO conformance report

`make conformance` writes this file on every run. Never edit it by hand.

The corpus holds the FoxIO commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`.

`docs/specs/features/04-conformance-harness.md` states the requirements this report holds.

## Summary

| Measure | Count |
|---|---|
| Captures | 38 |
| Matches | 1753 |
| Deviations | 270 |
| Accepted deviations | 583 |
| Unaccepted uncovered values | 172 |
| Accepted uncovered values | 32 |
| Accepted comparisons | 615 |
| Stale register entries | 0 |
| Orphan register entries | 0 |
| Captures the suite compared | 35 |
| Captures the suite compared nothing on | 3 |

The two vector sets cover different methods, so the report counts each one on its own.

| Vector set | Matches | Deviations | Accepted deviations | Unaccepted uncovered values | Accepted uncovered values |
|---|---|---|---|---|---|
| per-stream | 1116 | 44 | 281 | 144 | 14 |
| per-packet | 637 | 226 | 302 | 28 | 18 |

An accepted deviation is an entry of `testdata/deviations.json`, which records a ruling.
An accepted uncovered value is an entry of that file too, and `## Uncovered values` below states what an uncovered value is.
The register holds one entry for each accepted comparison, so the accepted comparison count equals the register key count.

## Deviations

The run reports 853 deviations in 76 groups. One group is one capture, one method and one vector set.

This file is tracked in git, so the table holds at most 3 deviations of each group. The `Deviations` column counts the whole group.
`conformance.log` holds every deviation, `make conformance` writes it in CI, and the conformance job uploads it as an artifact.

| Capture | Vector set | Method | Deviations | Comparison | Difference | Expected | Produced |
|---|---|---|---|---|---|---|---|
| `CVE-2018-6794.pcap` | per-packet | JA4H | 4 | `CVE-2018-6794.pcap/16/JA4H_r.1` | the two values differ (accepted) | `ge11nr06ruru_Host,Connection,User-Agent,Accept,Accept-Encoding,Accept-Language__` | `ge11nr06ruru_Host,Connection,User-Agent,Accept,Accept-Encoding,Accept-Language_` |
| `CVE-2018-6794.pcap` | per-packet | JA4H | 4 | `CVE-2018-6794.pcap/16/JA4H_ro.1` | the two values differ (accepted) | `ge11nr06ruru_Host,Connection,User-Agent,Accept,Accept-Encoding,Accept-Language__` | `ge11nr06ruru_Host,Connection,User-Agent,Accept,Accept-Encoding,Accept-Language_` |
| `CVE-2018-6794.pcap` | per-packet | JA4H | 4 | `CVE-2018-6794.pcap/6/JA4H_r.1` | the two values differ (accepted) | `ge11nn07ruru_Host,Connection,User-Agent,Upgrade-Insecure-Requests,Accept,Accept-Encoding,Accept-Language__` | `ge11nn07ruru_Host,Connection,User-Agent,Upgrade-Insecure-Requests,Accept,Accept-Encoding,Accept-Language_` |
| `badcurveball.pcap` | per-packet | JA4L | 3 | `badcurveball.pcap/3/JA4L.1` | the library produces a value the vector does not hold | (none) | `2177_64` |
| `badcurveball.pcap` | per-packet | JA4L | 3 | `badcurveball.pcap/4/JA4L.1` | the library produces a value the vector does not hold (accepted) | (none) | `2181_64` |
| `badcurveball.pcap` | per-packet | JA4L | 3 | `badcurveball.pcap/9/JA4L.1` | the vector holds a value the library does not produce | `2177_64_114797` | (none) |
| `badcurveball.pcap` | per-packet | JA4LS | 2 | `badcurveball.pcap/2/JA4LS.1` | the library produces a value the vector does not hold | (none) | `781_238` |
| `badcurveball.pcap` | per-packet | JA4LS | 2 | `badcurveball.pcap/9/JA4LS.1` | the vector holds a value the library does not produce | `781_238_9042` | (none) |
| `browsers-x509.pcapng` | per-packet | JA4L | 9 | `browsers-x509.pcapng/10/JA4L.1` | the vector holds a value the library does not produce | `56_128_3758` | (none) |
| `browsers-x509.pcapng` | per-packet | JA4L | 9 | `browsers-x509.pcapng/122/JA4L.1` | the library produces a value the vector does not hold | (none) | `78_128` |
| `browsers-x509.pcapng` | per-packet | JA4L | 9 | `browsers-x509.pcapng/123/JA4L.1` | the library produces a value the vector does not hold (accepted) | (none) | `247_128` |
| `browsers-x509.pcapng` | per-packet | JA4LS | 6 | `browsers-x509.pcapng/10/JA4LS.1` | the vector holds a value the library does not produce | `1907_112_343076` | (none) |
| `browsers-x509.pcapng` | per-packet | JA4LS | 6 | `browsers-x509.pcapng/121/JA4LS.1` | the library produces a value the vector does not hold | (none) | `2948_229` |
| `browsers-x509.pcapng` | per-packet | JA4LS | 6 | `browsers-x509.pcapng/128/JA4LS.1` | the vector holds a value the library does not produce | `2948_229_14055` | (none) |
| `browsers-x509.pcapng` | per-packet | JA4S | 2 | `browsers-x509.pcapng/8/JA4S.1` | the vector holds a value the library does not produce | `t1206h2_c030_044dc9b3196d` | (none) |
| `browsers-x509.pcapng` | per-packet | JA4S | 2 | `browsers-x509.pcapng/8/JA4S_r.1` | the vector holds a value the library does not produce | `t1206h2_c030_0005,0023,0010,0017,ff01,0000` | (none) |
| `browsers-x509.pcapng` | per-packet | JA4TS | 1 | `browsers-x509.pcapng/119/JA4TS.1` | the library produces a value the vector does not hold (accepted) | (none) | `64240_2-1-3-4-0-0_1460_2` |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-packet | JA4H | 3 | `chrome-cloudflare-quic-with-secrets.pcapng/12/JA4H.1` | the vector holds a value the library does not produce | `ge20nn12enus_60f823d07c94_000000000000_000000000000` | (none) |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-packet | JA4H | 3 | `chrome-cloudflare-quic-with-secrets.pcapng/12/JA4H_r.1` | the vector holds a value the library does not produce | `ge20nn12enus_sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,user-agent,accept,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language__` | (none) |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-packet | JA4H | 3 | `chrome-cloudflare-quic-with-secrets.pcapng/12/JA4H_ro.1` | the vector holds a value the library does not produce | `ge20nn12enus_sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,user-agent,accept,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language__` | (none) |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-packet | JA4L | 3 | `chrome-cloudflare-quic-with-secrets.pcapng/3/JA4L.1` | the library produces a value the vector does not hold | (none) | `30_64` |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-packet | JA4L | 3 | `chrome-cloudflare-quic-with-secrets.pcapng/4/JA4L.1` | the library produces a value the vector does not hold (accepted) | (none) | `149_64` |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-packet | JA4L | 3 | `chrome-cloudflare-quic-with-secrets.pcapng/52/JA4L.1` | the two values differ | `264_0_quic` | `113_64_quic` |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-packet | JA4LS | 2 | `chrome-cloudflare-quic-with-secrets.pcapng/2/JA4LS.1` | the library produces a value the vector does not hold | (none) | `5749_56` |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-packet | JA4LS | 2 | `chrome-cloudflare-quic-with-secrets.pcapng/52/JA4LS.1` | the two values differ | `9285_0_quic` | `9285_56_quic` |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-stream | JA4 | 4 | `chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4` | the library produces a value the vector does not hold | (none) | `q13d0310h3_55b375c5d22e_cd85d2d88918` |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-stream | JA4 | 4 | `chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4_o` | the library produces a value the vector does not hold | (none) | `q13d0310h3_55b375c5d22e_045e0fa1773b` |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-stream | JA4 | 4 | `chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4_r` | the library produces a value the vector does not hold | (none) | `q13d0310h3_1301,1302,1303_000a,000d,001b,002b,002d,0033,0039,4469_0403,0804,0401,0503,0805,0501,0806,0601,0201` |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-stream | JA4H | 2 | `chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4H` | the vector holds a value the library does not produce | `ge20nn12enus_60f823d07c94_000000000000_000000000000` | (none) |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-stream | JA4H | 2 | `chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4H_ro` | the vector holds a value the library does not produce | `ge20nn12enus_sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,user-agent,accept,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language_` | (none) |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-stream | JA4L | 1 | `chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4L-C` | the two values differ (accepted) | `113_64` | `113_64_quic` |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-stream | JA4LS | 1 | `chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4L-S` | the two values differ | `10990_56` | `9285_56_quic` |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-stream | JA4S | 2 | `chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4S` | the library produces a value the vector does not hold (accepted) | (none) | `q130200_1301_234ea6891581` |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-stream | JA4S | 2 | `chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4S_r` | the library produces a value the vector does not hold (accepted) | (none) | `q130200_1301_0033,002b` |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-stream | JA4X | 2 | `chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4X.1` | the vector holds a value the library does not produce | `a373a9f83c6b_2bab15409345_7bf9a7bf7029` | (none) |
| `chrome-cloudflare-quic-with-secrets.pcapng` | per-stream | JA4X | 2 | `chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4X.2` | the vector holds a value the library does not produce | `7d5dbb3783b4_a373a9f83c6b_44440d41940c` | (none) |
| `gre-erspan-vxlan.pcap` | per-packet | JA4H | 3 | `gre-erspan-vxlan.pcap/4/JA4H.1` | the vector holds a value the library does not produce | `ge10nn000000_e3b0c44298fc_000000000000_000000000000` | (none) |
| `gre-erspan-vxlan.pcap` | per-packet | JA4H | 3 | `gre-erspan-vxlan.pcap/4/JA4H_r.1` | the vector holds a value the library does not produce | `ge10nn000000___` | (none) |
| `gre-erspan-vxlan.pcap` | per-packet | JA4H | 3 | `gre-erspan-vxlan.pcap/4/JA4H_ro.1` | the vector holds a value the library does not produce | `ge10nn000000___` | (none) |
| `gre-sample.pcap` | per-packet | JA4SSH | 1 | `gre-sample.pcap/31/JA4SSH.1` | the vector holds a value the library does not produce (accepted) | `c24s23_c4s4_c5s4` | (none) |
| `http-empty-useragent.pcap` | per-packet | JA4H | 2 | `http-empty-useragent.pcap/9/JA4H_r.1` | the two values differ (accepted) | `ge10nn010000_User-Agent__` | `ge10nn010000_User-Agent_` |
| `http-empty-useragent.pcap` | per-packet | JA4H | 2 | `http-empty-useragent.pcap/9/JA4H_ro.1` | the two values differ (accepted) | `ge10nn010000_User-Agent__` | `ge10nn010000_User-Agent_` |
| `http1-with-cookies.pcapng` | per-packet | JA4H | 1 | `http1-with-cookies.pcapng/5/JA4H_ro.1` | the two values differ (accepted) | `ge11cr04da00_Host,User-Agent,Accept,Accept-Language_yummy_cookie,tasty_cookie_yummy_cookie=choco,tasty_cookie=strawberry,` | `ge11cr04da00_Host,User-Agent,Accept,Accept-Language_yummy_cookie,tasty_cookie_yummy_cookie=choco,tasty_cookie=strawberry` |
| `http1.pcapng` | per-packet | JA4H | 112 | `http1.pcapng/10/JA4H_r.1` | the two values differ (accepted) | `po11nn050000_Host,Accept,User-Agent,Content-Type,Content-Length__` | `po11nn050000_Host,Accept,User-Agent,Content-Type,Content-Length_` |
| `http1.pcapng` | per-packet | JA4H | 112 | `http1.pcapng/10/JA4H_ro.1` | the two values differ (accepted) | `po11nn050000_Host,Accept,User-Agent,Content-Type,Content-Length__` | `po11nn050000_Host,Accept,User-Agent,Content-Type,Content-Length_` |
| `http1.pcapng` | per-packet | JA4H | 112 | `http1.pcapng/100/JA4H_r.1` | the two values differ (accepted) | `ge11nn050000_Host,Date,User-Agent,X-AV-Physical-Unit-Info,X-AV-Client-Info__` | `ge11nn050000_Host,Date,User-Agent,X-AV-Physical-Unit-Info,X-AV-Client-Info_` |
| `http2-with-cookies.pcapng` | per-packet | JA4H | 45 | `http2-with-cookies.pcapng/15/JA4H.1` | the vector holds a value the library does not produce | `ge20cn19enus_cb83bf27b7a9_c7713052b7e4_348cad68b6fb` | (none) |
| `http2-with-cookies.pcapng` | per-packet | JA4H | 45 | `http2-with-cookies.pcapng/15/JA4H_r.1` | the vector holds a value the library does not produce | `ge20cn19enus_sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,user-agent,accept,sec-ch-ua-arch,sec-ch-ua-platform-version,sec-ch-ua-model,sec-ch-ua-bitness,sec-ch-ua-wow64,sec-ch-ua-full-version-list,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language_APISID,HSID,LOGIN_INFO,SAPISID,SID,SSID,VISITOR_INFO1_LIVE,__Secure-1PAPISID,__Secure-1PSID,__Secure-1PSIDTS,__Secure-3PAPISID,__Secure-3PSID,__Secure-3PSIDCC,__Secure-3PSIDTS_APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,HSID=AOF5tyazl7ZAKFyZY,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,SSID=AqFHwVpJHIK9H1lfZ,VISITOR_INFO1_LIVE=5CuVaSL9wDE,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,__Secure-3PSIDCC=APoG2W80ReNqY71qp2I8hZk8BsmVmWk_ejh3LtS-HuboNyHI73aZAnaQhqTWkTHUiz45rCPv,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA` | (none) |
| `http2-with-cookies.pcapng` | per-packet | JA4H | 45 | `http2-with-cookies.pcapng/15/JA4H_ro.1` | the vector holds a value the library does not produce | `ge20cn19enus_sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,user-agent,accept,sec-ch-ua-arch,sec-ch-ua-platform-version,sec-ch-ua-model,sec-ch-ua-bitness,sec-ch-ua-wow64,sec-ch-ua-full-version-list,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language_VISITOR_INFO1_LIVE,LOGIN_INFO,SID,__Secure-1PSIDTS,__Secure-3PSIDTS,__Secure-1PSID,__Secure-3PSID,HSID,SSID,APISID,SAPISID,__Secure-1PAPISID,__Secure-3PAPISID,__Secure-3PSIDCC_VISITOR_INFO1_LIVE=5CuVaSL9wDE,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,HSID=AOF5tyazl7ZAKFyZY,SSID=AqFHwVpJHIK9H1lfZ,APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PSIDCC=APoG2W80ReNqY71qp2I8hZk8BsmVmWk_ejh3LtS-HuboNyHI73aZAnaQhqTWkTHUiz45rCPv,` | (none) |
| `http2-with-cookies.pcapng` | per-packet | JA4L | 3 | `http2-with-cookies.pcapng/12/JA4L.1` | the vector holds a value the library does not produce | `47_128_455044` | (none) |
| `http2-with-cookies.pcapng` | per-packet | JA4L | 3 | `http2-with-cookies.pcapng/3/JA4L.1` | the library produces a value the vector does not hold | (none) | `47_128` |
| `http2-with-cookies.pcapng` | per-packet | JA4L | 3 | `http2-with-cookies.pcapng/4/JA4L.1` | the library produces a value the vector does not hold (accepted) | (none) | `470_128` |
| `http2-with-cookies.pcapng` | per-packet | JA4LS | 2 | `http2-with-cookies.pcapng/12/JA4LS.1` | the vector holds a value the library does not produce | `44840_117_48774` | (none) |
| `http2-with-cookies.pcapng` | per-packet | JA4LS | 2 | `http2-with-cookies.pcapng/2/JA4LS.1` | the library produces a value the vector does not hold | (none) | `44840_117` |
| `http2-with-cookies.pcapng` | per-packet | JA4X | 6 | `http2-with-cookies.pcapng/10/JA4X.1` | the vector holds a value the library does not produce | `a373a9f83c6b_7022c563de38_2e3757343cb0` | (none) |
| `http2-with-cookies.pcapng` | per-packet | JA4X | 6 | `http2-with-cookies.pcapng/10/JA4X.2` | the vector holds a value the library does not produce | `a373a9f83c6b_a373a9f83c6b_5d71497f7704` | (none) |
| `http2-with-cookies.pcapng` | per-packet | JA4X | 6 | `http2-with-cookies.pcapng/10/JA4X.3` | the vector holds a value the library does not produce | `7d5dbb3783b4_a373a9f83c6b_2fbee3f04f3b` | (none) |
| `http2-with-cookies.pcapng` | per-stream | JA4H | 30 | `http2-with-cookies.pcapng/0/JA4H.1` | the vector holds a value the library does not produce | `ge20cn19enus_cb83bf27b7a9_c7713052b7e4_348cad68b6fb` | (none) |
| `http2-with-cookies.pcapng` | per-stream | JA4H | 30 | `http2-with-cookies.pcapng/0/JA4H.10` | the vector holds a value the library does not produce | `ge20cr18enus_40430d236f7c_10ff48fdaa11_ac323afc21f7` | (none) |
| `http2-with-cookies.pcapng` | per-stream | JA4H | 30 | `http2-with-cookies.pcapng/0/JA4H.11` | the vector holds a value the library does not produce | `ge20cr18enus_40430d236f7c_10ff48fdaa11_ac323afc21f7` | (none) |
| `http2-with-cookies.pcapng` | per-stream | JA4X | 3 | `http2-with-cookies.pcapng/0/JA4X.1` | the vector holds a value the library does not produce | `a373a9f83c6b_7022c563de38_2e3757343cb0` | (none) |
| `http2-with-cookies.pcapng` | per-stream | JA4X | 3 | `http2-with-cookies.pcapng/0/JA4X.2` | the vector holds a value the library does not produce | `a373a9f83c6b_a373a9f83c6b_5d71497f7704` | (none) |
| `http2-with-cookies.pcapng` | per-stream | JA4X | 3 | `http2-with-cookies.pcapng/0/JA4X.3` | the vector holds a value the library does not produce | `7d5dbb3783b4_a373a9f83c6b_2fbee3f04f3b` | (none) |
| `https-connect.pcap` | per-packet | JA4H | 2 | `https-connect.pcap/4/JA4H_r.1` | the two values differ (accepted) | `co10nn010000_User-Agent__` | `co10nn010000_User-Agent_` |
| `https-connect.pcap` | per-packet | JA4H | 2 | `https-connect.pcap/4/JA4H_ro.1` | the two values differ (accepted) | `co10nn010000_User-Agent__` | `co10nn010000_User-Agent_` |
| `https-connect.pcap` | per-packet | JA4L | 2 | `https-connect.pcap/3/JA4L.1` | the library produces a value the vector does not hold | (none) | `45_64` |
| `https-connect.pcap` | per-packet | JA4L | 2 | `https-connect.pcap/8/JA4L.1` | the vector holds a value the library does not produce | `45_64_66` | (none) |
| `https-connect.pcap` | per-packet | JA4LS | 2 | `https-connect.pcap/2/JA4LS.1` | the library produces a value the vector does not hold | (none) | `13532_57` |
| `https-connect.pcap` | per-packet | JA4LS | 2 | `https-connect.pcap/8/JA4LS.1` | the vector holds a value the library does not produce | `13532_57_31654` | (none) |
| `https3-301-get.pcap` | per-packet | JA4L | 3 | `https3-301-get.pcap/10/JA4L.1` | the vector holds a value the library does not produce | `33_64_20332` | (none) |
| `https3-301-get.pcap` | per-packet | JA4L | 3 | `https3-301-get.pcap/3/JA4L.1` | the library produces a value the vector does not hold | (none) | `33_64` |
| `https3-301-get.pcap` | per-packet | JA4L | 3 | `https3-301-get.pcap/4/JA4L.1` | the library produces a value the vector does not hold (accepted) | (none) | `206_64` |
| `https3-301-get.pcap` | per-packet | JA4LS | 2 | `https3-301-get.pcap/10/JA4LS.1` | the vector holds a value the library does not produce | `17805_50_18217` | (none) |
| `https3-301-get.pcap` | per-packet | JA4LS | 2 | `https3-301-get.pcap/2/JA4LS.1` | the library produces a value the vector does not hold | (none) | `17805_50` |
| `https3-301-get.pcap` | per-packet | JA4TS | 3 | `https3-301-get.pcap/20/JA4TS.1` | the vector holds a value the library does not produce (accepted) | `14240_2-4-8-1-3_1436_10` | (none) |
| `https3-301-get.pcap` | per-packet | JA4TS | 3 | `https3-301-get.pcap/21/JA4TS.1` | the vector holds a value the library does not produce (accepted) | `14240_2-4-8-1-3_1436_10` | (none) |
| `https3-301-get.pcap` | per-packet | JA4TS | 3 | `https3-301-get.pcap/23/JA4TS.1` | the vector holds a value the library does not produce (accepted) | `14240_2-4-8-1-3_1436_10` | (none) |
| `latest.pcapng` | per-packet | JA4H | 11 | `latest.pcapng/113/JA4H_r.1` | the two values differ (accepted) | `ge11nn07enus_Host,Connection,User-Agent,Accept-Encoding,Accept-Language,If-None-Match,If-Modified-Since__` | `ge11nn07enus_Host,Connection,User-Agent,Accept-Encoding,Accept-Language,If-None-Match,If-Modified-Since_` |
| `latest.pcapng` | per-packet | JA4H | 11 | `latest.pcapng/113/JA4H_ro.1` | the two values differ (accepted) | `ge11nn07enus_Host,Connection,User-Agent,Accept-Encoding,Accept-Language,If-None-Match,If-Modified-Since__` | `ge11nn07enus_Host,Connection,User-Agent,Accept-Encoding,Accept-Language,If-None-Match,If-Modified-Since_` |
| `latest.pcapng` | per-packet | JA4H | 11 | `latest.pcapng/172/JA4H.1` | the vector holds a value the library does not produce (accepted) | `ms11nn040000_a3c882e23515_000000000000_000000000000` | (none) |
| `latest.pcapng` | per-packet | JA4L | 16 | `latest.pcapng/10/JA4L.1` | the library produces a value the vector does not hold (accepted) | (none) | `513_128` |
| `latest.pcapng` | per-packet | JA4L | 16 | `latest.pcapng/100/JA4L.1` | the library produces a value the vector does not hold | (none) | `47_128` |
| `latest.pcapng` | per-packet | JA4L | 16 | `latest.pcapng/101/JA4L.1` | the library produces a value the vector does not hold (accepted) | (none) | `188_128` |
| `latest.pcapng` | per-packet | JA4LS | 11 | `latest.pcapng/111/JA4LS.1` | the library produces a value the vector does not hold | (none) | `3915_57` |
| `latest.pcapng` | per-packet | JA4LS | 11 | `latest.pcapng/117/JA4LS.1` | the vector holds a value the library does not produce | `14207_43_18819` | (none) |
| `latest.pcapng` | per-packet | JA4LS | 11 | `latest.pcapng/156/JA4LS.1` | the library produces a value the vector does not hold | (none) | `42103_109` |
| `latest.pcapng` | per-packet | JA4S | 4 | `latest.pcapng/163/JA4S.1` | the vector holds a value the library does not produce | `t120300_c030_09f674154ab3` | (none) |
| `latest.pcapng` | per-packet | JA4S | 4 | `latest.pcapng/163/JA4S_r.1` | the vector holds a value the library does not produce | `t120300_c030_0005,0017,ff01` | (none) |
| `latest.pcapng` | per-packet | JA4S | 4 | `latest.pcapng/197/JA4S.1` | the vector holds a value the library does not produce | `t120300_c030_09f674154ab3` | (none) |
| `single-packets.pcap` | per-packet | JA4H | 11 | `single-packets.pcap/1/JA4H_ro.1` | the two values differ (accepted) | `ge11cr06enus_Accept,Accept-Language,User-Agent,Accept-Encoding,Host,Connection_IDE_IDE=AHWqTUmq5vKag4U1NoZpmbEiY1PYuAYVT8bFXA1KRM6sqXH_QR5G3_2xSz7V6E3B,` | `ge11cr06enus_Accept,Accept-Language,User-Agent,Accept-Encoding,Host,Connection_IDE_IDE=AHWqTUmq5vKag4U1NoZpmbEiY1PYuAYVT8bFXA1KRM6sqXH_QR5G3_2xSz7V6E3B` |
| `single-packets.pcap` | per-packet | JA4H | 11 | `single-packets.pcap/2/JA4H_ro.1` | the two values differ (accepted) | `ge11cr07enus_Accept,X-Requested-With,Accept-Language,Accept-Encoding,User-Agent,Host,Connection__ga,_gid,_gat,AMCV_A70E15F354E99A260A4C98A4%40AdobeOrg,AMCVS_A70E15F354E99A260A4C98A4%40AdobeOrg,mbox,s_dfa,s_cc,s_ppvl,s_ppv,s_sq,segmentid,aam_uuid,app_promotion__ga=GA1.2.349209205.1532525440,_gid=GA1.2.1042544967.1532525440,_gat=1,AMCV_A70E15F354E99A260A4C98A4%40AdobeOrg=-330454231%7CMCIDTS%7C17738%7CMCMID%7C00834244270283740751404491874386840551%7CMCAAMLH-1533130240%7C3%7CMCAAMB-1533130240%7C6G1ynYcLPuiQxYZrsz_pkqfLG9yMXBpb2zX5dvJdYQJzPXImdj0y%7CMCOPTOUT-1532532640s%7CNONE%7CMCSYNCSOP%7C411-17745%7CMCAID%7CNONE%7CvVersion%7C3.1.2,AMCVS_A70E15F354E99A260A4C98A4%40AdobeOrg=1,mbox=session#f11f91da64134d8183e8dda4dc10aaf4#1532527370|PC#f11f91da64134d8183e8dda4dc10aaf4.22_23#1540301510|check#true#1532525570,s_dfa=shgshg-web-global,s_cc=true,s_ppvl=www.shangri-la.com%2C52%2C52%2C499%2C1350%2C498%2C1350%2C615%2C1%2CL,s_ppv=www.shangri-la.com%2C48%2C48%2C498%2C1350%2C498%2C1350%2C615%2C1%2CL,s_sq=%5B%5BB%5D%5D,segmentid=segment%3DC%2Csegment%3Dtesting,aam_uuid=01107346641427687611431242460084872101,app_promotion=1,` | `ge11cr07enus_Accept,X-Requested-With,Accept-Language,Accept-Encoding,User-Agent,Host,Connection__ga,_gid,_gat,AMCV_A70E15F354E99A260A4C98A4%40AdobeOrg,AMCVS_A70E15F354E99A260A4C98A4%40AdobeOrg,mbox,s_dfa,s_cc,s_ppvl,s_ppv,s_sq,segmentid,aam_uuid,app_promotion__ga=GA1.2.349209205.1532525440,_gid=GA1.2.1042544967.1532525440,_gat=1,AMCV_A70E15F354E99A260A4C98A4%40AdobeOrg=-330454231%7CMCIDTS%7C17738%7CMCMID%7C00834244270283740751404491874386840551%7CMCAAMLH-1533130240%7C3%7CMCAAMB-1533130240%7C6G1ynYcLPuiQxYZrsz_pkqfLG9yMXBpb2zX5dvJdYQJzPXImdj0y%7CMCOPTOUT-1532532640s%7CNONE%7CMCSYNCSOP%7C411-17745%7CMCAID%7CNONE%7CvVersion%7C3.1.2,AMCVS_A70E15F354E99A260A4C98A4%40AdobeOrg=1,mbox=session#f11f91da64134d8183e8dda4dc10aaf4#1532527370|PC#f11f91da64134d8183e8dda4dc10aaf4.22_23#1540301510|check#true#1532525570,s_dfa=shgshg-web-global,s_cc=true,s_ppvl=www.shangri-la.com%2C52%2C52%2C499%2C1350%2C498%2C1350%2C615%2C1%2CL,s_ppv=www.shangri-la.com%2C48%2C48%2C498%2C1350%2C498%2C1350%2C615%2C1%2CL,s_sq=%5B%5BB%5D%5D,segmentid=segment%3DC%2Csegment%3Dtesting,aam_uuid=01107346641427687611431242460084872101,app_promotion=1` |
| `single-packets.pcap` | per-packet | JA4H | 11 | `single-packets.pcap/3/JA4H_r.1` | the two values differ (accepted) | `ge11nr06enus_Accept,Accept-Language,User-Agent,Accept-Encoding,Host,Connection__` | `ge11nr06enus_Accept,Accept-Language,User-Agent,Accept-Encoding,Host,Connection_` |
| `socks-https-example.pcap` | per-packet | JA4L | 9 | `socks-https-example.pcap/3/JA4L.1` | the library produces a value the vector does not hold | (none) | `23_64` |
| `socks-https-example.pcap` | per-packet | JA4L | 9 | `socks-https-example.pcap/33/JA4L.1` | the library produces a value the vector does not hold | (none) | `22_64` |
| `socks-https-example.pcap` | per-packet | JA4L | 9 | `socks-https-example.pcap/34/JA4L.1` | the library produces a value the vector does not hold (accepted) | (none) | `30_64` |
| `socks-https-example.pcap` | per-packet | JA4LS | 6 | `socks-https-example.pcap/2/JA4LS.1` | the library produces a value the vector does not hold | (none) | `210_64` |
| `socks-https-example.pcap` | per-packet | JA4LS | 6 | `socks-https-example.pcap/32/JA4LS.1` | the library produces a value the vector does not hold | (none) | `280_64` |
| `socks-https-example.pcap` | per-packet | JA4LS | 6 | `socks-https-example.pcap/38/JA4LS.1` | the vector holds a value the library does not produce | `280_64_18934` | (none) |
| `ssh-r.pcap` | per-packet | JA4L | 9 | `ssh-r.pcap/298/JA4L.1` | the library produces a value the vector does not hold | (none) | `14_64` |
| `ssh-r.pcap` | per-packet | JA4L | 9 | `ssh-r.pcap/299/JA4L.1` | the library produces a value the vector does not hold (accepted) | (none) | `2058_64` |
| `ssh-r.pcap` | per-packet | JA4L | 9 | `ssh-r.pcap/3/JA4L.1` | the library produces a value the vector does not hold | (none) | `94_128` |
| `ssh-r.pcap` | per-packet | JA4LS | 6 | `ssh-r.pcap/2/JA4LS.1` | the library produces a value the vector does not hold | (none) | `32_64` |
| `ssh-r.pcap` | per-packet | JA4LS | 6 | `ssh-r.pcap/297/JA4LS.1` | the library produces a value the vector does not hold | (none) | `4171_116` |
| `ssh-r.pcap` | per-packet | JA4LS | 6 | `ssh-r.pcap/304/JA4LS.1` | the vector holds a value the library does not produce | `4171_116_8099` | (none) |
| `ssh-r.pcap` | per-packet | JA4SSH | 3 | `ssh-r.pcap/1831/JA4SSH.1` | the vector holds a value the library does not produce (accepted) | `c76s76_c66s65_c9s52` | (none) |
| `ssh-r.pcap` | per-packet | JA4SSH | 3 | `ssh-r.pcap/1851/JA4SSH.1` | the vector holds a value the library does not produce (accepted) | `c64s64_c33s48_c41s2` | (none) |
| `ssh-r.pcap` | per-packet | JA4SSH | 3 | `ssh-r.pcap/339/JA4SSH.1` | the vector holds a value the library does not produce (accepted) | `c48s21_c6s5_c4s5` | (none) |
| `ssh-r.pcap` | per-stream | JA4SSH | 3 | `ssh-r.pcap/0/JA4SSH.2` | the two values differ (accepted) | `c64s64_c0s0_c0s1` | `c64s64_c33s48_c41s2` |
| `ssh-r.pcap` | per-stream | JA4SSH | 3 | `ssh-r.pcap/1/JA4SSH.1` | the two values differ (accepted) | `c64s64_c6s5_c4s5` | `c48s21_c6s5_c4s5` |
| `ssh-r.pcap` | per-stream | JA4SSH | 3 | `ssh-r.pcap/2/JA4SSH.1` | the two values differ (accepted) | `c64s64_c104s96_c19s82` | `c76s76_c104s96_c19s82` |
| `ssh-scp-1050.pcap` | per-packet | JA4L | 3 | `ssh-scp-1050.pcap/10/JA4L.1` | the vector holds a value the library does not produce | `179_128_2773` | (none) |
| `ssh-scp-1050.pcap` | per-packet | JA4L | 3 | `ssh-scp-1050.pcap/3/JA4L.1` | the library produces a value the vector does not hold | (none) | `179_128` |
| `ssh-scp-1050.pcap` | per-packet | JA4L | 3 | `ssh-scp-1050.pcap/4/JA4L.1` | the library produces a value the vector does not hold (accepted) | (none) | `6615_128` |
| `ssh-scp-1050.pcap` | per-packet | JA4LS | 2 | `ssh-scp-1050.pcap/10/JA4LS.1` | the vector holds a value the library does not produce | `38_64_1921` | (none) |
| `ssh-scp-1050.pcap` | per-packet | JA4LS | 2 | `ssh-scp-1050.pcap/2/JA4LS.1` | the library produces a value the vector does not hold | (none) | `38_64` |
| `ssh-scp-1050.pcap` | per-stream | JA4SSH | 3 | `ssh-scp-1050.pcap/0/JA4SSH.3` | the two values differ (accepted) | `c112s1460_c0s200_c36s0` | `c0s1460_c0s200_c36s0` |
| `ssh-scp-1050.pcap` | per-stream | JA4SSH | 3 | `ssh-scp-1050.pcap/0/JA4SSH.4` | the two values differ (accepted) | `c112s1460_c0s200_c23s0` | `c0s1460_c0s200_c23s0` |
| `ssh-scp-1050.pcap` | per-stream | JA4SSH | 3 | `ssh-scp-1050.pcap/0/JA4SSH.5` | the library produces a value the vector does not hold (accepted) | (none) | `c0s1460_c0s53_c6s0` |
| `ssh.pcapng` | per-stream | JA4SSH | 1 | `ssh.pcapng/0/JA4SSH.2` | the library produces a value the vector does not hold (accepted) | (none) | `c36s52_c42s76_c0s0` |
| `ssh2-malformed.pcap` | per-packet | JA4L | 3 | `ssh2-malformed.pcap/11/JA4L.1` | the vector holds a value the library does not produce | `7_64_45` | (none) |
| `ssh2-malformed.pcap` | per-packet | JA4L | 3 | `ssh2-malformed.pcap/3/JA4L.1` | the library produces a value the vector does not hold | (none) | `7_64` |
| `ssh2-malformed.pcap` | per-packet | JA4L | 3 | `ssh2-malformed.pcap/4/JA4L.1` | the library produces a value the vector does not hold (accepted) | (none) | `6310_64` |
| `ssh2-malformed.pcap` | per-packet | JA4LS | 2 | `ssh2-malformed.pcap/11/JA4LS.1` | the vector holds a value the library does not produce | `462_60_984` | (none) |
| `ssh2-malformed.pcap` | per-packet | JA4LS | 2 | `ssh2-malformed.pcap/2/JA4LS.1` | the library produces a value the vector does not hold | (none) | `462_60` |
| `ssh2-moloch-crash.pcap` | per-packet | JA4L | 3 | `ssh2-moloch-crash.pcap/11/JA4L.1` | the vector holds a value the library does not produce | `7_64_45` | (none) |
| `ssh2-moloch-crash.pcap` | per-packet | JA4L | 3 | `ssh2-moloch-crash.pcap/3/JA4L.1` | the library produces a value the vector does not hold | (none) | `7_64` |
| `ssh2-moloch-crash.pcap` | per-packet | JA4L | 3 | `ssh2-moloch-crash.pcap/4/JA4L.1` | the library produces a value the vector does not hold (accepted) | (none) | `6310_64` |
| `ssh2-moloch-crash.pcap` | per-packet | JA4LS | 2 | `ssh2-moloch-crash.pcap/11/JA4LS.1` | the vector holds a value the library does not produce | `462_60_984` | (none) |
| `ssh2-moloch-crash.pcap` | per-packet | JA4LS | 2 | `ssh2-moloch-crash.pcap/2/JA4LS.1` | the library produces a value the vector does not hold | (none) | `462_60` |
| `ssh2.pcapng` | per-packet | JA4H | 91 | `ssh2.pcapng/1025/JA4H.1` | the vector holds a value the library does not produce (accepted) | `ms11nn050000_2ba00a982a15_000000000000_000000000000` | (none) |
| `ssh2.pcapng` | per-packet | JA4H | 91 | `ssh2.pcapng/1025/JA4H_r.1` | the vector holds a value the library does not produce (accepted) | `ms11nn050000_HOST,MAN,MX,ST,USER-AGENT__` | (none) |
| `ssh2.pcapng` | per-packet | JA4H | 91 | `ssh2.pcapng/1025/JA4H_ro.1` | the vector holds a value the library does not produce (accepted) | `ms11nn050000_HOST,MAN,MX,ST,USER-AGENT__` | (none) |
| `ssh2.pcapng` | per-packet | JA4L | 21 | `ssh2.pcapng/1046/JA4L.1` | the vector holds a value the library does not produce | `279_128_quic` | (none) |
| `ssh2.pcapng` | per-packet | JA4L | 21 | `ssh2.pcapng/158/JA4L.1` | the library produces a value the vector does not hold | (none) | `56_128` |
| `ssh2.pcapng` | per-packet | JA4L | 21 | `ssh2.pcapng/159/JA4L.1` | the library produces a value the vector does not hold (accepted) | (none) | `234_128` |
| `ssh2.pcapng` | per-packet | JA4LS | 15 | `ssh2.pcapng/1046/JA4LS.1` | the vector holds a value the library does not produce | `16192_57_quic` | (none) |
| `ssh2.pcapng` | per-packet | JA4LS | 15 | `ssh2.pcapng/157/JA4LS.1` | the library produces a value the vector does not hold | (none) | `55492_235` |
| `ssh2.pcapng` | per-packet | JA4LS | 15 | `ssh2.pcapng/170/JA4LS.1` | the vector holds a value the library does not produce | `55492_235_57471` | (none) |
| `ssh2.pcapng` | per-packet | JA4S | 4 | `ssh2.pcapng/237/JA4S.1` | the vector holds a value the library does not produce | `t120300_c030_09f674154ab3` | (none) |
| `ssh2.pcapng` | per-packet | JA4S | 4 | `ssh2.pcapng/237/JA4S_r.1` | the vector holds a value the library does not produce | `t120300_c030_0005,0017,ff01` | (none) |
| `ssh2.pcapng` | per-packet | JA4S | 4 | `ssh2.pcapng/259/JA4S.1` | the vector holds a value the library does not produce | `t1205h2_c030_015e35fdd027` | (none) |
| `ssh2.pcapng` | per-stream | JA4 | 8 | `ssh2.pcapng/33/JA4` | the library produces a value the vector does not hold (accepted) | (none) | `q13d0312h3_55b375c5d22e_73e2d9e6cde6` |
| `ssh2.pcapng` | per-stream | JA4 | 8 | `ssh2.pcapng/33/JA4_o` | the library produces a value the vector does not hold (accepted) | (none) | `q13d0312h3_55b375c5d22e_fde15aea1603` |
| `ssh2.pcapng` | per-stream | JA4 | 8 | `ssh2.pcapng/33/JA4_r` | the library produces a value the vector does not hold (accepted) | (none) | `q13d0312h3_1301,1302,1303_000a,000d,001b,0029,002a,002b,002d,0033,0039,4469_0403,0804,0401,0503,0805,0501,0806,0601,0201` |
| `ssh2.pcapng` | per-stream | JA4L | 1 | `ssh2.pcapng/36/JA4L-C` | the two values differ (accepted) | `169_128` | `169_128_quic` |
| `ssh2.pcapng` | per-stream | JA4LS | 2 | `ssh2.pcapng/33/JA4L-S` | the vector holds a value the library does not produce | `16192_57` | (none) |
| `ssh2.pcapng` | per-stream | JA4LS | 2 | `ssh2.pcapng/36/JA4L-S` | the two values differ (accepted) | `5389_57` | `5389_57_quic` |
| `ssh2.pcapng` | per-stream | JA4S | 4 | `ssh2.pcapng/33/JA4S` | the library produces a value the vector does not hold (accepted) | (none) | `q130300_1301_6bbbaf601ed8` |
| `ssh2.pcapng` | per-stream | JA4S | 4 | `ssh2.pcapng/33/JA4S_r` | the library produces a value the vector does not hold (accepted) | (none) | `q130300_1301_0029,0033,002b` |
| `ssh2.pcapng` | per-stream | JA4S | 4 | `ssh2.pcapng/36/JA4S` | the library produces a value the vector does not hold (accepted) | (none) | `q130200_1301_234ea6891581` |
| `ssh2.pcapng` | per-stream | JA4SSH | 1 | `ssh2.pcapng/14/JA4SSH.2` | the two values differ (accepted) | `c36s36_c0s0_c2s0` | `c36s52_c42s76_c51s2` |
| `sshv1.pcap` | per-packet | JA4SSH | 4 | `sshv1.pcap/72/JA4SSH.1` | the two values differ (accepted) | `c20s12_c18s21_c10s1` | `c20s20_c18s25_c10s1` |
| `sshv1.pcap` | per-packet | JA4SSH | 4 | `sshv1.pcap/73/JA4SSH.1` | the vector holds a value the library does not produce (accepted) | `c20s12_c18s21_c10s1` | (none) |
| `sshv1.pcap` | per-packet | JA4SSH | 4 | `sshv1.pcap/74/JA4SSH.1` | the vector holds a value the library does not produce (accepted) | `c20s12_c18s21_c10s1` | (none) |
| `tcpdump-geneve.pcap` | per-packet | JA4L | 3 | `tcpdump-geneve.pcap/13/JA4L.1` | the vector holds a value the library does not produce | `93_64_124` | (none) |
| `tcpdump-geneve.pcap` | per-packet | JA4L | 3 | `tcpdump-geneve.pcap/5/JA4L.1` | the library produces a value the vector does not hold | (none) | `93_64` |
| `tcpdump-geneve.pcap` | per-packet | JA4L | 3 | `tcpdump-geneve.pcap/6/JA4L.1` | the library produces a value the vector does not hold (accepted) | (none) | `3418_64` |
| `tcpdump-geneve.pcap` | per-packet | JA4LS | 2 | `tcpdump-geneve.pcap/13/JA4LS.1` | the vector holds a value the library does not produce | `24_64_380` | (none) |
| `tcpdump-geneve.pcap` | per-packet | JA4LS | 2 | `tcpdump-geneve.pcap/4/JA4LS.1` | the library produces a value the vector does not hold | (none) | `24_64` |
| `tls-handshake.pcapng` | per-packet | JA4S | 2 | `tls-handshake.pcapng/151/JA4S.1` | the vector holds a value the library does not produce | `t120400_c030_4e8089b08790` | (none) |
| `tls-handshake.pcapng` | per-packet | JA4S | 2 | `tls-handshake.pcapng/151/JA4S_r.1` | the vector holds a value the library does not produce | `t120400_c030_0005,0017,ff01,0000` | (none) |
| `tls-handshake.pcapng` | per-stream | JA4 | 80 | `tls-handshake.pcapng/142.251.111.101:443-192.168.1.168:60486/JA4` | the library produces a value the vector does not hold (accepted) | (none) | `q13d0310h3_55b375c5d22e_cd85d2d88918` |
| `tls-handshake.pcapng` | per-stream | JA4 | 80 | `tls-handshake.pcapng/142.251.111.101:443-192.168.1.168:60486/JA4_o` | the library produces a value the vector does not hold (accepted) | (none) | `q13d0310h3_55b375c5d22e_69d12ce3ef74` |
| `tls-handshake.pcapng` | per-stream | JA4 | 80 | `tls-handshake.pcapng/142.251.111.101:443-192.168.1.168:60486/JA4_r` | the library produces a value the vector does not hold (accepted) | (none) | `q13d0310h3_1301,1302,1303_000a,000d,001b,002b,002d,0033,0039,4469_0403,0804,0401,0503,0805,0501,0806,0601,0201` |
| `tls-handshake.pcapng` | per-stream | JA4S | 50 | `tls-handshake.pcapng/142.251.111.101:443-192.168.1.168:60486/JA4S` | the library produces a value the vector does not hold (accepted) | (none) | `q130200_1301_234ea6891581` |
| `tls-handshake.pcapng` | per-stream | JA4S | 50 | `tls-handshake.pcapng/142.251.111.101:443-192.168.1.168:60486/JA4S_r` | the library produces a value the vector does not hold (accepted) | (none) | `q130200_1301_0033,002b` |
| `tls-handshake.pcapng` | per-stream | JA4S | 50 | `tls-handshake.pcapng/142.251.111.101:443-192.168.1.168:61836/JA4S` | the library produces a value the vector does not hold (accepted) | (none) | `q130200_1301_234ea6891581` |
| `tls-sni.pcapng` | per-stream | JA4 | 80 | `tls-sni.pcapng/142.251.111.101:443-192.168.1.168:60486/JA4` | the library produces a value the vector does not hold (accepted) | (none) | `q13d0310h3_55b375c5d22e_cd85d2d88918` |
| `tls-sni.pcapng` | per-stream | JA4 | 80 | `tls-sni.pcapng/142.251.111.101:443-192.168.1.168:60486/JA4_o` | the library produces a value the vector does not hold (accepted) | (none) | `q13d0310h3_55b375c5d22e_69d12ce3ef74` |
| `tls-sni.pcapng` | per-stream | JA4 | 80 | `tls-sni.pcapng/142.251.111.101:443-192.168.1.168:60486/JA4_r` | the library produces a value the vector does not hold (accepted) | (none) | `q13d0310h3_1301,1302,1303_000a,000d,001b,002b,002d,0033,0039,4469_0403,0804,0401,0503,0805,0501,0806,0601,0201` |
| `tls3.pcapng` | per-packet | JA4H | 14 | `tls3.pcapng/47/JA4H.1` | the vector holds a value the library does not produce (accepted) | `ms11nn050000_1ae2aaf984bf_000000000000_000000000000` | (none) |
| `tls3.pcapng` | per-packet | JA4H | 14 | `tls3.pcapng/47/JA4H_r.1` | the vector holds a value the library does not produce (accepted) | `ms11nn050000_Host,Content-Length,MAN,MX,ST__` | (none) |
| `tls3.pcapng` | per-packet | JA4H | 14 | `tls3.pcapng/47/JA4H_ro.1` | the vector holds a value the library does not produce (accepted) | `ms11nn050000_Host,Content-Length,MAN,MX,ST__` | (none) |
| `tls3.pcapng` | per-packet | JA4L | 27 | `tls3.pcapng/147/JA4L.1` | the two values differ (accepted) | `90_128_quic` | `59_128_quic` |
| `tls3.pcapng` | per-packet | JA4L | 27 | `tls3.pcapng/153/JA4L.1` | the two values differ | `101_128_quic` | `40_128_quic` |
| `tls3.pcapng` | per-packet | JA4L | 27 | `tls3.pcapng/167/JA4L.1` | the two values differ (accepted) | `81_128_quic` | `59_128_quic` |
| `tls3.pcapng` | per-packet | JA4LS | 16 | `tls3.pcapng/170/JA4LS.1` | the library produces a value the vector does not hold | (none) | `2442_57` |
| `tls3.pcapng` | per-packet | JA4LS | 16 | `tls3.pcapng/214/JA4LS.1` | the vector holds a value the library does not produce | `2442_57_3520` | (none) |
| `tls3.pcapng` | per-packet | JA4LS | 16 | `tls3.pcapng/276/JA4LS.1` | the library produces a value the vector does not hold | (none) | `34691_38` |
| `tls3.pcapng` | per-stream | JA4 | 24 | `tls3.pcapng/21/JA4` | the library produces a value the vector does not hold (accepted) | (none) | `q13d0310h3_55b375c5d22e_cd85d2d88918` |
| `tls3.pcapng` | per-stream | JA4 | 24 | `tls3.pcapng/21/JA4_o` | the library produces a value the vector does not hold (accepted) | (none) | `q13d0310h3_55b375c5d22e_985e08bbd12b` |
| `tls3.pcapng` | per-stream | JA4 | 24 | `tls3.pcapng/21/JA4_r` | the library produces a value the vector does not hold (accepted) | (none) | `q13d0310h3_1301,1302,1303_000a,000d,001b,002b,002d,0033,0039,4469_0403,0804,0401,0503,0805,0501,0806,0601,0201` |
| `tls3.pcapng` | per-stream | JA4L | 5 | `tls3.pcapng/21/JA4L-C` | the two values differ (accepted) | `59_128` | `59_128_quic` |
| `tls3.pcapng` | per-stream | JA4L | 5 | `tls3.pcapng/22/JA4L-C` | the two values differ (accepted) | `336_128` | `336_128_quic` |
| `tls3.pcapng` | per-stream | JA4L | 5 | `tls3.pcapng/23/JA4L-C` | the two values differ (accepted) | `40_128` | `40_128_quic` |
| `tls3.pcapng` | per-stream | JA4LS | 6 | `tls3.pcapng/21/JA4L-S` | the two values differ (accepted) | `4213_59` | `4213_59_quic` |
| `tls3.pcapng` | per-stream | JA4LS | 6 | `tls3.pcapng/22/JA4L-S` | the two values differ (accepted) | `5580_57` | `5580_57_quic` |
| `tls3.pcapng` | per-stream | JA4LS | 6 | `tls3.pcapng/23/JA4L-S` | the two values differ (accepted) | `4455_58` | `4455_58_quic` |
| `tls3.pcapng` | per-stream | JA4S | 12 | `tls3.pcapng/21/JA4S` | the library produces a value the vector does not hold (accepted) | (none) | `q130200_1301_234ea6891581` |
| `tls3.pcapng` | per-stream | JA4S | 12 | `tls3.pcapng/21/JA4S_r` | the library produces a value the vector does not hold (accepted) | (none) | `q130200_1301_0033,002b` |
| `tls3.pcapng` | per-stream | JA4S | 12 | `tls3.pcapng/22/JA4S` | the library produces a value the vector does not hold (accepted) | (none) | `q130200_1301_234ea6891581` |
| `v6.pcap` | per-packet | JA4SSH | 4 | `v6.pcap/72/JA4SSH.1` | the two values differ (accepted) | `c20s12_c18s21_c10s1` | `c20s20_c18s25_c10s1` |
| `v6.pcap` | per-packet | JA4SSH | 4 | `v6.pcap/73/JA4SSH.1` | the vector holds a value the library does not produce (accepted) | `c20s12_c18s21_c10s1` | (none) |
| `v6.pcap` | per-packet | JA4SSH | 4 | `v6.pcap/74/JA4SSH.1` | the vector holds a value the library does not produce (accepted) | `c20s12_c18s21_c10s1` | (none) |

## Uncovered values

The library produces a value, and the vector file of the capture publishes no key for its method. Such a file states nothing about the method. The run therefore counts the value apart from a match, and apart from a deviation. The maintainer ruled the third category on 2026-08-13 in #361.

The count below holds the accepted values and the unaccepted ones. The summary above counts the two apart.

The run reports 204 uncovered values in 59 groups, and the register accepts 32 of them. One group is one capture, one method and one vector set.

This file is tracked in git, so the table holds at most 3 uncovered values of each group. The `Uncovered` column counts the whole group.

| Capture | Vector set | Method | Uncovered | Comparison | Produced | Accepted |
|---|---|---|---|---|---|---|
| `CVE-2018-6794.pcap` | per-packet | JA4L | 3 | `CVE-2018-6794.pcap/12/JA4L.1` | `1_128` | yes |
| `CVE-2018-6794.pcap` | per-packet | JA4L | 3 | `CVE-2018-6794.pcap/21/JA4L.1` | `1_128` | yes |
| `CVE-2018-6794.pcap` | per-packet | JA4L | 3 | `CVE-2018-6794.pcap/3/JA4L.1` | `1_128` | yes |
| `CVE-2018-6794.pcap` | per-packet | JA4LS | 3 | `CVE-2018-6794.pcap/11/JA4LS.1` | `1513_255` | yes |
| `CVE-2018-6794.pcap` | per-packet | JA4LS | 3 | `CVE-2018-6794.pcap/2/JA4LS.1` | `2219_255` | yes |
| `CVE-2018-6794.pcap` | per-packet | JA4LS | 3 | `CVE-2018-6794.pcap/20/JA4LS.1` | `1948_255` | yes |
| `CVE-2018-6794.pcap` | per-stream | JA4H | 2 | `CVE-2018-6794.pcap/0/JA4H_r` | `ge11nn07ruru_Host,Connection,User-Agent,Upgrade-Insecure-Requests,Accept,Accept-Encoding,Accept-Language_` | no |
| `CVE-2018-6794.pcap` | per-stream | JA4H | 2 | `CVE-2018-6794.pcap/1/JA4H_r` | `ge11nr06ruru_Host,Connection,User-Agent,Accept,Accept-Encoding,Accept-Language_` | no |
| `CVE-2018-6794.pcap` | per-stream | JA4L | 3 | `CVE-2018-6794.pcap/0/JA4L-C` | `1_128` | yes |
| `CVE-2018-6794.pcap` | per-stream | JA4L | 3 | `CVE-2018-6794.pcap/1/JA4L-C` | `1_128` | yes |
| `CVE-2018-6794.pcap` | per-stream | JA4L | 3 | `CVE-2018-6794.pcap/192.168.235.1:53648-192.168.235.136:8089/JA4L-C` | `1_128` | yes |
| `CVE-2018-6794.pcap` | per-stream | JA4LS | 3 | `CVE-2018-6794.pcap/0/JA4L-S` | `2219_255` | yes |
| `CVE-2018-6794.pcap` | per-stream | JA4LS | 3 | `CVE-2018-6794.pcap/1/JA4L-S` | `1513_255` | yes |
| `CVE-2018-6794.pcap` | per-stream | JA4LS | 3 | `CVE-2018-6794.pcap/192.168.235.1:53648-192.168.235.136:8089/JA4L-S` | `1948_255` | yes |
| `badcurveball.pcap` | per-stream | JA4X | 2 | `badcurveball.pcap/0/JA4X_r` | `550406,550408,55040a,550403_550406,55040a,550403_551d13,551d11,551d0e,551d0f,551d25` | no |
| `badcurveball.pcap` | per-stream | JA4X | 2 | `badcurveball.pcap/0/JA4X_r.2` | `550406,550408,55040a,550403_550406,550408,55040a,550403_551d0e,551d23,551d13` | no |
| `browsers-x509.pcapng` | per-stream | JA4X | 7 | `browsers-x509.pcapng/0/JA4X_r` | `550406,55040a,550403_550406,550408,550407,55040a,550403_2b06010401d679020402,2b060104018237150a,2b0601040182371507,2b06010505070101,551d0e,551d0f,551d11,551d13,551d1f,551d20,551d23,551d25` | no |
| `browsers-x509.pcapng` | per-stream | JA4X | 7 | `browsers-x509.pcapng/0/JA4X_r.2` | `550406,55040a,55040b,550403_550406,55040a,550403_551d0e,551d23,551d0f,551d25,551d13,2b06010505070101,551d1f,551d20,2b0601040182371501` | no |
| `browsers-x509.pcapng` | per-stream | JA4X | 7 | `browsers-x509.pcapng/1/JA4X_r` | `550406,55040a,55040b,550403_550406,550408,550407,55040a,550403_551d23,551d0e,551d11,551d0f,551d25,551d1f,551d20,2b06010505070101,551d13,2b06010401d679020402` | no |
| `gre-erspan-vxlan.pcap` | per-packet | JA4L | 1 | `gre-erspan-vxlan.pcap/3/JA4L.1` | `953_64` | no |
| `gre-erspan-vxlan.pcap` | per-packet | JA4LS | 1 | `gre-erspan-vxlan.pcap/2/JA4LS.1` | `997_64` | no |
| `gre-sample.pcap` | per-packet | JA4L | 2 | `gre-sample.pcap/13/JA4L.1` | `36_255` | yes |
| `gre-sample.pcap` | per-packet | JA4L | 2 | `gre-sample.pcap/14/JA4L.1` | `26150_255` | yes |
| `gre-sample.pcap` | per-packet | JA4LS | 1 | `gre-sample.pcap/12/JA4LS.1` | `22952_236` | yes |
| `gre-sample.pcap` | per-packet | JA4T | 1 | `gre-sample.pcap/11/JA4T.1` | `5744_2-4-8-1-3_1436_00` | no |
| `gre-sample.pcap` | per-packet | JA4TS | 1 | `gre-sample.pcap/12/JA4TS.1` | `5792_2-4-8-1-3_1460_00` | no |
| `gre-sample.pcap` | per-stream | JA4SSH | 1 | `gre-sample.pcap/0/JA4SSH` | `c24s23_c4s4_c5s4` | no |
| `http-empty-useragent.pcap` | per-packet | JA4L | 3 | `http-empty-useragent.pcap/3/JA4L.1` | `5_64` | no |
| `http-empty-useragent.pcap` | per-packet | JA4L | 3 | `http-empty-useragent.pcap/4/JA4L.1` | `10_64` | no |
| `http-empty-useragent.pcap` | per-packet | JA4L | 3 | `http-empty-useragent.pcap/5/JA4L.1` | `177863_64` | no |
| `http-empty-useragent.pcap` | per-packet | JA4LS | 1 | `http-empty-useragent.pcap/2/JA4LS.1` | `26_64` | no |
| `http-empty-useragent.pcap` | per-stream | JA4H | 1 | `http-empty-useragent.pcap/0/JA4H_r` | `ge10nn010000_User-Agent_` | no |
| `http1-with-cookies.pcapng` | per-packet | JA4L | 2 | `http1-with-cookies.pcapng/3/JA4L.1` | `14_64` | no |
| `http1-with-cookies.pcapng` | per-packet | JA4L | 2 | `http1-with-cookies.pcapng/4/JA4L.1` | `20_64` | no |
| `http1-with-cookies.pcapng` | per-packet | JA4LS | 1 | `http1-with-cookies.pcapng/2/JA4LS.1` | `64_64` | no |
| `http1-with-cookies.pcapng` | per-stream | JA4H | 1 | `http1-with-cookies.pcapng/0/JA4H_r` | `ge11cr04da00_Host,User-Agent,Accept,Accept-Language_tasty_cookie,yummy_cookie_tasty_cookie=strawberry,yummy_cookie=choco` | no |
| `http1.pcapng` | per-stream | JA4H | 56 | `http1.pcapng/0/JA4H_r` | `po11nn050000_Host,Accept,User-Agent,Content-Type,Content-Length_` | no |
| `http1.pcapng` | per-stream | JA4H | 56 | `http1.pcapng/1/JA4H_r` | `po11nn050000_Host,Accept,User-Agent,Content-Type,Content-Length_` | no |
| `http1.pcapng` | per-stream | JA4H | 56 | `http1.pcapng/10/JA4H_r` | `po11nn050000_Host,Accept,User-Agent,Content-Type,Content-Length_` | no |
| `https-connect.pcap` | per-stream | JA4 | 4 | `https-connect.pcap/0/JA4` | `t12i860500_e18388e7f3a3_a1e935682795` | no |
| `https-connect.pcap` | per-stream | JA4 | 4 | `https-connect.pcap/0/JA4_o` | `t12i860500_42de6d1d033a_318da70f1e40` | no |
| `https-connect.pcap` | per-stream | JA4 | 4 | `https-connect.pcap/0/JA4_r` | `t12i860500_0004,0005,0007,000a,000d,0010,0013,0016,002f,0030,0031,0032,0033,0035,0036,0037,0038,0039,003c,003d,003e,003f,0040,0041,0042,0043,0044,0045,0067,0068,0069,006a,006b,0084,0085,0086,0087,0088,0096,0097,0098,0099,009a,009c,009d,009e,009f,00a0,00a1,00a2,00a3,00a4,00a5,00ff,c002,c003,c004,c005,c007,c008,c009,c00a,c00c,c00d,c00e,c00f,c011,c012,c013,c014,c023,c024,c025,c026,c027,c028,c029,c02a,c02b,c02c,c02d,c02e,c02f,c030,c031,c032_000a,000b,000d,000f,0023_0601,0602,0603,0501,0502,0503,0401,0402,0403,0301,0302,0303,0201,0202,0203` | no |
| `https-connect.pcap` | per-stream | JA4H | 1 | `https-connect.pcap/0/JA4H_r` | `co10nn010000_User-Agent_` | no |
| `https-connect.pcap` | per-stream | JA4L | 1 | `https-connect.pcap/0/JA4L-C` | `45_64` | yes |
| `https-connect.pcap` | per-stream | JA4LS | 1 | `https-connect.pcap/0/JA4L-S` | `13532_57` | yes |
| `https-connect.pcap` | per-stream | JA4S | 2 | `https-connect.pcap/0/JA4S` | `t120200_c030_5fbb12310400` | no |
| `https-connect.pcap` | per-stream | JA4S | 2 | `https-connect.pcap/0/JA4S_r` | `t120200_c030_0023,ff01` | no |
| `https-connect.pcap` | per-stream | JA4X | 4 | `https-connect.pcap/0/JA4X` | `7d5dbb3783b4_2bab15409345_5e17a2514980` | no |
| `https-connect.pcap` | per-stream | JA4X | 4 | `https-connect.pcap/0/JA4X.2` | `7d5dbb3783b4_7d5dbb3783b4_9c5875a5c227` | no |
| `https-connect.pcap` | per-stream | JA4X | 4 | `https-connect.pcap/0/JA4X_r` | `550406,55040a,55040b,550403_550406,550408,550407,55040a,550403_551d23,551d0e,551d11,551d0f,551d25,551d1f,551d20,2b06010505070101,551d13` | no |
| `https3-301-get.pcap` | per-stream | JA4X | 2 | `https3-301-get.pcap/0/JA4X_r` | `550406,55040a,55040b,550403_55040f,2b0601040182373c020103,2b0601040182373c020102,550405,550409,550411,550406,550408,550407,55040a,550403_551d23,551d0e,551d11,551d0f,551d25,551d1f,551d20,2b06010505070101,551d13` | no |
| `https3-301-get.pcap` | per-stream | JA4X | 2 | `https3-301-get.pcap/0/JA4X_r.2` | `550406,55040a,55040b,550403_550406,55040a,55040b,550403_551d0f,551d25,551d20,551d13,2b06010505070101,551d1f,551d0e,551d23` | no |
| `ipv6.pcapng` | per-packet | JA4L | 2 | `ipv6.pcapng/3/JA4L.1` | `35_64` | no |
| `ipv6.pcapng` | per-packet | JA4L | 2 | `ipv6.pcapng/4/JA4L.1` | `3911_64` | no |
| `ipv6.pcapng` | per-packet | JA4LS | 1 | `ipv6.pcapng/2/JA4LS.1` | `18861_59` | no |
| `ipv6.pcapng` | per-stream | JA4X | 2 | `ipv6.pcapng/0/JA4X_r` | `550406,55040a,55040b,550403_55040f,2b0601040182373c020103,2b0601040182373c020102,550405,550406,550408,550407,55040a,550403_551d23,551d0e,551d11,551d0f,551d25,551d1f,551d20,2b06010505070101,551d13,2b06010401d679020402` | no |
| `ipv6.pcapng` | per-stream | JA4X | 2 | `ipv6.pcapng/0/JA4X_r.2` | `550406,55040a,55040b,550403_550406,55040a,55040b,550403_551d0e,551d23,551d13,551d0f,2b06010505070101,551d1f,551d20` | no |
| `latest.pcapng` | per-stream | JA4H | 1 | `latest.pcapng/6/JA4H_r` | `ge11nn07enus_Host,Connection,User-Agent,Accept-Encoding,Accept-Language,If-None-Match,If-Modified-Since_` | no |
| `latest.pcapng` | per-stream | JA4X | 8 | `latest.pcapng/1/JA4X_r` | `550406,55040a,550403_550406,550408,550407,55040a,550403_551d23,551d0e,551d11,551d0f,551d25,551d1f,551d20,2b06010505070101,551d13,2b06010401d679020402` | no |
| `latest.pcapng` | per-stream | JA4X | 8 | `latest.pcapng/1/JA4X_r.2` | `550406,55040a,55040b,550403_550406,55040a,550403_551d13,551d0e,551d23,551d0f,551d25,2b06010505070101,551d1f,551d20` | no |
| `latest.pcapng` | per-stream | JA4X | 8 | `latest.pcapng/10/JA4X_r` | `550406,55040a,550403_550406,550408,550407,55040a,550403_2b06010401d679020402,2b060104018237150a,2b0601040182371507,2b06010505070101,551d0e,551d0f,551d11,551d13,551d1f,551d20,551d23,551d25` | no |
| `macos_tcp_flags.pcap` | per-packet | JA4L | 2 | `macos_tcp_flags.pcap/3/JA4L.1` | `62_64` | yes |
| `macos_tcp_flags.pcap` | per-packet | JA4L | 2 | `macos_tcp_flags.pcap/4/JA4L.1` | `393_64` | yes |
| `macos_tcp_flags.pcap` | per-packet | JA4LS | 1 | `macos_tcp_flags.pcap/2/JA4LS.1` | `17255_63` | yes |
| `macos_tcp_flags.pcap` | per-packet | JA4T | 1 | `macos_tcp_flags.pcap/1/JA4T.1` | `65535_2-1-3-1-1-8-4-0-0_1460_6` | no |
| `macos_tcp_flags.pcap` | per-packet | JA4TS | 1 | `macos_tcp_flags.pcap/2/JA4TS.1` | `65160_2-4-8-1-3_1134_8` | no |
| `single-packets.pcap` | per-stream | JA4H | 8 | `single-packets.pcap/0/JA4H_r` | `ge11cr06enus_Accept,Accept-Language,User-Agent,Accept-Encoding,Host,Connection_IDE_IDE=AHWqTUmq5vKag4U1NoZpmbEiY1PYuAYVT8bFXA1KRM6sqXH_QR5G3_2xSz7V6E3B` | no |
| `single-packets.pcap` | per-stream | JA4H | 8 | `single-packets.pcap/1/JA4H_r` | `ge11cr07enus_Accept,X-Requested-With,Accept-Language,Accept-Encoding,User-Agent,Host,Connection_AMCVS_A70E15F354E99A260A4C98A4%40AdobeOrg,AMCV_A70E15F354E99A260A4C98A4%40AdobeOrg,_ga,_gat,_gid,aam_uuid,app_promotion,mbox,s_cc,s_dfa,s_ppv,s_ppvl,s_sq,segmentid_AMCVS_A70E15F354E99A260A4C98A4%40AdobeOrg=1,AMCV_A70E15F354E99A260A4C98A4%40AdobeOrg=-330454231%7CMCIDTS%7C17738%7CMCMID%7C00834244270283740751404491874386840551%7CMCAAMLH-1533130240%7C3%7CMCAAMB-1533130240%7C6G1ynYcLPuiQxYZrsz_pkqfLG9yMXBpb2zX5dvJdYQJzPXImdj0y%7CMCOPTOUT-1532532640s%7CNONE%7CMCSYNCSOP%7C411-17745%7CMCAID%7CNONE%7CvVersion%7C3.1.2,_ga=GA1.2.349209205.1532525440,_gat=1,_gid=GA1.2.1042544967.1532525440,aam_uuid=01107346641427687611431242460084872101,app_promotion=1,mbox=session#f11f91da64134d8183e8dda4dc10aaf4#1532527370|PC#f11f91da64134d8183e8dda4dc10aaf4.22_23#1540301510|check#true#1532525570,s_cc=true,s_dfa=shgshg-web-global,s_ppv=www.shangri-la.com%2C48%2C48%2C498%2C1350%2C498%2C1350%2C615%2C1%2CL,s_ppvl=www.shangri-la.com%2C52%2C52%2C499%2C1350%2C498%2C1350%2C615%2C1%2CL,s_sq=%5B%5BB%5D%5D,segmentid=segment%3DC%2Csegment%3Dtesting` | no |
| `single-packets.pcap` | per-stream | JA4H | 8 | `single-packets.pcap/2/JA4H_r` | `ge11nr06enus_Accept,Accept-Language,User-Agent,Accept-Encoding,Host,Connection_` | no |
| `socks-https-example.pcap` | per-stream | JA4X | 6 | `socks-https-example.pcap/0/JA4X_r` | `550406,55040a,55040b,550403_550406,550408,550407,55040a,550403_551d23,551d0e,551d11,551d0f,551d25,551d1f,551d20,2b06010505070101,551d13` | no |
| `socks-https-example.pcap` | per-stream | JA4X | 6 | `socks-https-example.pcap/0/JA4X_r.2` | `550406,55040a,55040b,550403_550406,55040a,55040b,550403_551d0f,551d20,551d13,2b06010505070101,551d1f,551d23,551d0e` | no |
| `socks-https-example.pcap` | per-stream | JA4X | 6 | `socks-https-example.pcap/2/JA4X_r` | `550406,55040a,55040b,550403_550406,550408,550407,55040a,550403_551d23,551d0e,551d11,551d0f,551d25,551d1f,551d20,2b06010505070101,551d13` | no |
| `socks4-https.pcap` | per-packet | JA4L | 2 | `socks4-https.pcap/3/JA4L.1` | `119349_126` | no |
| `socks4-https.pcap` | per-packet | JA4L | 2 | `socks4-https.pcap/4/JA4L.1` | `119433_126` | no |
| `socks4-https.pcap` | per-packet | JA4LS | 1 | `socks4-https.pcap/2/JA4LS.1` | `40155_52` | no |
| `socks4-https.pcap` | per-packet | JA4X | 6 | `socks4-https.pcap/16/JA4X.1` | `14f85a9f494d_3f8190b6b671_80ea7ef3b044` | yes |
| `socks4-https.pcap` | per-packet | JA4X | 6 | `socks4-https.pcap/16/JA4X.2` | `14f85a9f494d_14f85a9f494d_be007da94c85` | yes |
| `socks4-https.pcap` | per-packet | JA4X | 6 | `socks4-https.pcap/16/JA4X.3` | `e7bc7ebc3d9e_14f85a9f494d_9c8ed4a87d4b` | yes |
| `socks4-https.pcap` | per-stream | JA4X | 6 | `socks4-https.pcap/0/JA4X` | `14f85a9f494d_3f8190b6b671_80ea7ef3b044` | yes |
| `socks4-https.pcap` | per-stream | JA4X | 6 | `socks4-https.pcap/0/JA4X.2` | `14f85a9f494d_14f85a9f494d_be007da94c85` | yes |
| `socks4-https.pcap` | per-stream | JA4X | 6 | `socks4-https.pcap/0/JA4X.3` | `e7bc7ebc3d9e_14f85a9f494d_9c8ed4a87d4b` | yes |
| `ssh2-malformed.pcap` | per-stream | JA4SSH | 1 | `ssh2-malformed.pcap/0/JA4SSH` | `c16s23_c7s6_c3s4` | no |
| `ssh2-moloch-crash.pcap` | per-stream | JA4SSH | 1 | `ssh2-moloch-crash.pcap/0/JA4SSH` | `c16s23_c7s6_c3s4` | no |
| `ssh2.pcapng` | per-stream | JA4H | 2 | `ssh2.pcapng/15/JA4H_r` | `ge11nn030000_Connection,User-Agent,Host_` | no |
| `ssh2.pcapng` | per-stream | JA4H | 2 | `ssh2.pcapng/22/JA4H_r` | `ge11nn030000_Connection,User-Agent,Host_` | no |
| `ssh2.pcapng` | per-stream | JA4X | 12 | `ssh2.pcapng/11/JA4X_r` | `550406,55040a,550403_550406,550408,550407,55040a,550403_2b06010401d679020402,2b060104018237150a,2b0601040182371507,2b06010505070101,551d0e,551d0f,551d11,551d13,551d1f,551d20,551d23,551d25` | no |
| `ssh2.pcapng` | per-stream | JA4X | 12 | `ssh2.pcapng/11/JA4X_r.2` | `550406,55040a,55040b,550403_550406,55040a,550403_551d0e,551d23,551d0f,551d25,551d13,2b06010505070101,551d1f,551d20,2b0601040182371501` | no |
| `ssh2.pcapng` | per-stream | JA4X | 12 | `ssh2.pcapng/12/JA4X_r` | `550406,55040a,550403_550403_2b06010401d679020402,2b060104018237150a,2b0601040182371507,2b06010505070101,551d0e,551d0f,551d11,551d1f,551d20,551d23,551d25` | no |
| `sshv1.pcap` | per-packet | JA4L | 2 | `sshv1.pcap/18/JA4L.1` | `271_64` | no |
| `sshv1.pcap` | per-packet | JA4L | 2 | `sshv1.pcap/19/JA4L.1` | `39940_64` | no |
| `sshv1.pcap` | per-packet | JA4LS | 1 | `sshv1.pcap/17/JA4LS.1` | `28494_61` | no |
| `sshv1.pcap` | per-stream | JA4SSH | 1 | `sshv1.pcap/0/JA4SSH` | `c20s20_c18s25_c10s1` | no |
| `tcpdump-geneve.pcap` | per-stream | JA4SSH | 1 | `tcpdump-geneve.pcap/0/JA4SSH` | `c144s48_c10s11_c6s4` | no |
| `tls-alpn-h2.pcap` | per-packet | JA4L | 2 | `tls-alpn-h2.pcap/3/JA4L.1` | `35_64` | no |
| `tls-alpn-h2.pcap` | per-packet | JA4L | 2 | `tls-alpn-h2.pcap/4/JA4L.1` | `3911_64` | no |
| `tls-alpn-h2.pcap` | per-packet | JA4LS | 1 | `tls-alpn-h2.pcap/2/JA4LS.1` | `18861_59` | no |
| `tls-alpn-h2.pcap` | per-stream | JA4X | 2 | `tls-alpn-h2.pcap/0/JA4X_r` | `550406,55040a,55040b,550403_55040f,2b0601040182373c020103,2b0601040182373c020102,550405,550406,550408,550407,55040a,550403_551d23,551d0e,551d11,551d0f,551d25,551d1f,551d20,2b06010505070101,551d13,2b06010401d679020402` | no |
| `tls-alpn-h2.pcap` | per-stream | JA4X | 2 | `tls-alpn-h2.pcap/0/JA4X_r.2` | `550406,55040a,55040b,550403_550406,55040a,55040b,550403_551d0e,551d23,551d13,551d0f,2b06010505070101,551d1f,551d20` | no |
| `tls-handshake.pcapng` | per-stream | JA4X | 14 | `tls-handshake.pcapng/33/JA4X_r` | `550406,55040a,550403_550406,550408,550407,55040a,550403_551d23,551d0e,551d11,551d0f,551d25,551d1f,551d20,2b06010505070101,551d13,2b06010401d679020402` | no |
| `tls-handshake.pcapng` | per-stream | JA4X | 14 | `tls-handshake.pcapng/33/JA4X_r.2` | `550406,55040a,55040b,550403_550406,55040a,550403_551d13,551d0e,551d23,551d0f,551d25,2b06010505070101,551d1f,551d20` | no |
| `tls-handshake.pcapng` | per-stream | JA4X | 14 | `tls-handshake.pcapng/34/JA4X_r` | `550406,55040a,550403_550406,550408,550407,55040a,550403_551d23,551d0e,551d11,551d0f,551d25,551d1f,551d20,2b06010505070101,551d13,2b06010401d679020402` | no |
| `tls3.pcapng` | per-stream | JA4H | 1 | `tls3.pcapng/8/JA4H_r` | `ge11nn07enus_Host,Connection,User-Agent,Accept-Encoding,Accept-Language,If-None-Match,If-Modified-Since_` | no |
| `v6.pcap` | per-packet | JA4L | 2 | `v6.pcap/18/JA4L.1` | `271_64` | no |
| `v6.pcap` | per-packet | JA4L | 2 | `v6.pcap/19/JA4L.1` | `39940_64` | no |
| `v6.pcap` | per-packet | JA4LS | 1 | `v6.pcap/17/JA4LS.1` | `28494_61` | no |
| `v6.pcap` | per-stream | JA4SSH | 1 | `v6.pcap/0/JA4SSH` | `c20s20_c18s25_c10s1` | no |

## Stale register entries

An entry of `testdata/deviations.json` records the value this library produced when the maintainer ruled. A later change moves that value, and the entry then accepts a comparison it does not describe.

The run reports no stale register entry.

## Orphan register entries

An entry of `testdata/deviations.json` names one comparison. No comparison of the run reaches the key of an entry below, so the entry accepts a difference the run never measures.

The run reports no orphan register entry.

## Results

The table holds one row for each capture and each method. A row records `not applicable` only where no vector of the corpus holds a value for that method on that capture.

| Capture | Method | Vector set | Result | Matches | Deviations | Reason |
|---|---|---|---|---|---|---|
| `CVE-2018-6794.pcap` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `CVE-2018-6794.pcap` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `CVE-2018-6794.pcap` | JA4H | per-packet and per-stream | deviation | 6 | 4 | — |
| `CVE-2018-6794.pcap` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `CVE-2018-6794.pcap` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `CVE-2018-6794.pcap` | JA4L | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `CVE-2018-6794.pcap` | JA4LS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `CVE-2018-6794.pcap` | JA4T | per-packet | match | 3 | 0 | — |
| `CVE-2018-6794.pcap` | JA4TS | per-packet | match | 3 | 0 | — |
| `CVE-2018-6794.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `CVE-2018-6794.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `badcurveball.pcap` | JA4 | per-stream | match | 4 | 0 | — |
| `badcurveball.pcap` | JA4S | per-packet and per-stream | match | 4 | 0 | — |
| `badcurveball.pcap` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `badcurveball.pcap` | JA4X | per-packet and per-stream | match | 6 | 0 | — |
| `badcurveball.pcap` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `badcurveball.pcap` | JA4L | per-packet and per-stream | deviation | 1 | 3 | — |
| `badcurveball.pcap` | JA4LS | per-packet and per-stream | deviation | 1 | 2 | — |
| `badcurveball.pcap` | JA4T | per-packet | match | 1 | 0 | — |
| `badcurveball.pcap` | JA4TS | per-packet | match | 1 | 0 | — |
| `badcurveball.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `badcurveball.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `browsers-x509.pcapng` | JA4 | per-stream | match | 12 | 0 | — |
| `browsers-x509.pcapng` | JA4S | per-packet and per-stream | deviation | 8 | 2 | — |
| `browsers-x509.pcapng` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `browsers-x509.pcapng` | JA4X | per-packet and per-stream | match | 21 | 0 | — |
| `browsers-x509.pcapng` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `browsers-x509.pcapng` | JA4L | per-packet and per-stream | deviation | 3 | 9 | — |
| `browsers-x509.pcapng` | JA4LS | per-packet and per-stream | deviation | 3 | 6 | — |
| `browsers-x509.pcapng` | JA4T | per-packet | match | 3 | 0 | — |
| `browsers-x509.pcapng` | JA4TS | per-packet | deviation | 4 | 1 | — |
| `browsers-x509.pcapng` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `browsers-x509.pcapng` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `chrome-cloudflare-quic-with-secrets.pcapng` | JA4 | per-stream | deviation | 4 | 4 | — |
| `chrome-cloudflare-quic-with-secrets.pcapng` | JA4S | per-packet and per-stream | deviation | 6 | 2 | — |
| `chrome-cloudflare-quic-with-secrets.pcapng` | JA4H | per-packet and per-stream | deviation | 0 | 5 | — |
| `chrome-cloudflare-quic-with-secrets.pcapng` | JA4X | per-stream | deviation | 0 | 2 | — |
| `chrome-cloudflare-quic-with-secrets.pcapng` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `chrome-cloudflare-quic-with-secrets.pcapng` | JA4L | per-packet and per-stream | deviation | 1 | 4 | — |
| `chrome-cloudflare-quic-with-secrets.pcapng` | JA4LS | per-packet and per-stream | deviation | 1 | 3 | — |
| `chrome-cloudflare-quic-with-secrets.pcapng` | JA4T | per-packet | match | 1 | 0 | — |
| `chrome-cloudflare-quic-with-secrets.pcapng` | JA4TS | per-packet | match | 1 | 0 | — |
| `chrome-cloudflare-quic-with-secrets.pcapng` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `chrome-cloudflare-quic-with-secrets.pcapng` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `dhcp.pcapng` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcp.pcapng` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcp.pcapng` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcp.pcapng` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcp.pcapng` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcp.pcapng` | JA4L | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcp.pcapng` | JA4LS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcp.pcapng` | JA4T | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcp.pcapng` | JA4TS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcp.pcapng` | JA4D | per-packet | match | 4 | 0 | — |
| `dhcp.pcapng` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `dhcpv6.pcap` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcpv6.pcap` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcpv6.pcap` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcpv6.pcap` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcpv6.pcap` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcpv6.pcap` | JA4L | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcpv6.pcap` | JA4LS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcpv6.pcap` | JA4T | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcpv6.pcap` | JA4TS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `dhcpv6.pcap` | JA4D | per-packet | match | 6 | 0 | — |
| `dhcpv6.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `dtls-udp.notest.cap` | JA4 | — | not applicable | 0 | 0 | FoxIO marks the capture `notest`, so the suite compares no value on it. |
| `dtls-udp.notest.cap` | JA4S | — | not applicable | 0 | 0 | FoxIO marks the capture `notest`, so the suite compares no value on it. |
| `dtls-udp.notest.cap` | JA4H | — | not applicable | 0 | 0 | FoxIO marks the capture `notest`, so the suite compares no value on it. |
| `dtls-udp.notest.cap` | JA4X | — | not applicable | 0 | 0 | FoxIO marks the capture `notest`, so the suite compares no value on it. |
| `dtls-udp.notest.cap` | JA4SSH | — | not applicable | 0 | 0 | FoxIO marks the capture `notest`, so the suite compares no value on it. |
| `dtls-udp.notest.cap` | JA4L | — | not applicable | 0 | 0 | FoxIO marks the capture `notest`, so the suite compares no value on it. |
| `dtls-udp.notest.cap` | JA4LS | — | not applicable | 0 | 0 | FoxIO marks the capture `notest`, so the suite compares no value on it. |
| `dtls-udp.notest.cap` | JA4T | — | not applicable | 0 | 0 | FoxIO marks the capture `notest`, so the suite compares no value on it. |
| `dtls-udp.notest.cap` | JA4TS | — | not applicable | 0 | 0 | FoxIO marks the capture `notest`, so the suite compares no value on it. |
| `dtls-udp.notest.cap` | JA4D | — | not applicable | 0 | 0 | FoxIO marks the capture `notest`, so the suite compares no value on it. |
| `dtls-udp.notest.cap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO marks the capture `notest`, so the suite compares no value on it. |
| `gre-erspan-vxlan.pcap` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `gre-erspan-vxlan.pcap` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `gre-erspan-vxlan.pcap` | JA4H | per-packet | deviation | 0 | 3 | — |
| `gre-erspan-vxlan.pcap` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `gre-erspan-vxlan.pcap` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `gre-erspan-vxlan.pcap` | JA4L | per-stream | match | 1 | 0 | — |
| `gre-erspan-vxlan.pcap` | JA4LS | per-stream | match | 1 | 0 | — |
| `gre-erspan-vxlan.pcap` | JA4T | per-packet | match | 1 | 0 | — |
| `gre-erspan-vxlan.pcap` | JA4TS | per-packet | match | 1 | 0 | — |
| `gre-erspan-vxlan.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `gre-erspan-vxlan.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `gre-sample.pcap` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `gre-sample.pcap` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `gre-sample.pcap` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `gre-sample.pcap` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `gre-sample.pcap` | JA4SSH | per-packet | deviation | 1 | 1 | — |
| `gre-sample.pcap` | JA4L | per-stream | match | 1 | 0 | — |
| `gre-sample.pcap` | JA4LS | per-stream | match | 1 | 0 | — |
| `gre-sample.pcap` | JA4T | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `gre-sample.pcap` | JA4TS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `gre-sample.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `gre-sample.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `http-empty-useragent.pcap` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http-empty-useragent.pcap` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http-empty-useragent.pcap` | JA4H | per-packet and per-stream | deviation | 3 | 2 | — |
| `http-empty-useragent.pcap` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http-empty-useragent.pcap` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http-empty-useragent.pcap` | JA4L | per-stream | match | 1 | 0 | — |
| `http-empty-useragent.pcap` | JA4LS | per-stream | match | 1 | 0 | — |
| `http-empty-useragent.pcap` | JA4T | per-packet | match | 1 | 0 | — |
| `http-empty-useragent.pcap` | JA4TS | per-packet | match | 1 | 0 | — |
| `http-empty-useragent.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http-empty-useragent.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `http1-with-cookies.pcapng` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http1-with-cookies.pcapng` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http1-with-cookies.pcapng` | JA4H | per-packet and per-stream | deviation | 4 | 1 | — |
| `http1-with-cookies.pcapng` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http1-with-cookies.pcapng` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http1-with-cookies.pcapng` | JA4L | per-stream | match | 1 | 0 | — |
| `http1-with-cookies.pcapng` | JA4LS | per-stream | match | 1 | 0 | — |
| `http1-with-cookies.pcapng` | JA4T | per-packet | match | 1 | 0 | — |
| `http1-with-cookies.pcapng` | JA4TS | per-packet | match | 1 | 0 | — |
| `http1-with-cookies.pcapng` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http1-with-cookies.pcapng` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `http1.pcapng` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http1.pcapng` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http1.pcapng` | JA4H | per-packet and per-stream | deviation | 168 | 112 | — |
| `http1.pcapng` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http1.pcapng` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http1.pcapng` | JA4L | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http1.pcapng` | JA4LS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http1.pcapng` | JA4T | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http1.pcapng` | JA4TS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http1.pcapng` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http1.pcapng` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `http2-with-cookies.pcapng` | JA4 | per-stream | match | 4 | 0 | — |
| `http2-with-cookies.pcapng` | JA4S | per-packet and per-stream | match | 4 | 0 | — |
| `http2-with-cookies.pcapng` | JA4H | per-packet and per-stream | deviation | 0 | 75 | — |
| `http2-with-cookies.pcapng` | JA4X | per-packet and per-stream | deviation | 0 | 9 | — |
| `http2-with-cookies.pcapng` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http2-with-cookies.pcapng` | JA4L | per-packet and per-stream | deviation | 1 | 3 | — |
| `http2-with-cookies.pcapng` | JA4LS | per-packet and per-stream | deviation | 1 | 2 | — |
| `http2-with-cookies.pcapng` | JA4T | per-packet | match | 1 | 0 | — |
| `http2-with-cookies.pcapng` | JA4TS | per-packet | match | 1 | 0 | — |
| `http2-with-cookies.pcapng` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `http2-with-cookies.pcapng` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `https-connect.pcap` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `https-connect.pcap` | JA4S | per-packet | match | 2 | 0 | — |
| `https-connect.pcap` | JA4H | per-packet and per-stream | deviation | 3 | 2 | — |
| `https-connect.pcap` | JA4X | per-packet | match | 4 | 0 | — |
| `https-connect.pcap` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `https-connect.pcap` | JA4L | per-packet | deviation | 0 | 2 | — |
| `https-connect.pcap` | JA4LS | per-packet | deviation | 0 | 2 | — |
| `https-connect.pcap` | JA4T | per-packet | match | 1 | 0 | — |
| `https-connect.pcap` | JA4TS | per-packet | match | 1 | 0 | — |
| `https-connect.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `https-connect.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `https3-301-get.pcap` | JA4 | per-stream | match | 4 | 0 | — |
| `https3-301-get.pcap` | JA4S | per-packet and per-stream | match | 4 | 0 | — |
| `https3-301-get.pcap` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `https3-301-get.pcap` | JA4X | per-packet and per-stream | match | 6 | 0 | — |
| `https3-301-get.pcap` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `https3-301-get.pcap` | JA4L | per-packet and per-stream | deviation | 1 | 3 | — |
| `https3-301-get.pcap` | JA4LS | per-packet and per-stream | deviation | 1 | 2 | — |
| `https3-301-get.pcap` | JA4T | per-packet | match | 1 | 0 | — |
| `https3-301-get.pcap` | JA4TS | per-packet | deviation | 1 | 3 | — |
| `https3-301-get.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `https3-301-get.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `ipv6.pcapng` | JA4 | per-stream | match | 4 | 0 | — |
| `ipv6.pcapng` | JA4S | per-packet and per-stream | match | 4 | 0 | — |
| `ipv6.pcapng` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ipv6.pcapng` | JA4X | per-packet and per-stream | match | 6 | 0 | — |
| `ipv6.pcapng` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ipv6.pcapng` | JA4L | per-stream | match | 1 | 0 | — |
| `ipv6.pcapng` | JA4LS | per-stream | match | 1 | 0 | — |
| `ipv6.pcapng` | JA4T | per-packet | match | 1 | 0 | — |
| `ipv6.pcapng` | JA4TS | per-packet | match | 1 | 0 | — |
| `ipv6.pcapng` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ipv6.pcapng` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `latest.pcapng` | JA4 | per-stream | match | 20 | 0 | — |
| `latest.pcapng` | JA4S | per-packet and per-stream | deviation | 12 | 4 | — |
| `latest.pcapng` | JA4H | per-packet and per-stream | deviation | 3 | 11 | — |
| `latest.pcapng` | JA4X | per-packet and per-stream | match | 24 | 0 | — |
| `latest.pcapng` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `latest.pcapng` | JA4L | per-packet and per-stream | deviation | 6 | 16 | — |
| `latest.pcapng` | JA4LS | per-packet and per-stream | deviation | 6 | 11 | — |
| `latest.pcapng` | JA4T | per-packet | match | 6 | 0 | — |
| `latest.pcapng` | JA4TS | per-packet | match | 6 | 0 | — |
| `latest.pcapng` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `latest.pcapng` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `macos_tcp_flags.pcap` | JA4 | per-stream | match | 4 | 0 | — |
| `macos_tcp_flags.pcap` | JA4S | per-packet and per-stream | match | 4 | 0 | — |
| `macos_tcp_flags.pcap` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `macos_tcp_flags.pcap` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `macos_tcp_flags.pcap` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `macos_tcp_flags.pcap` | JA4L | per-stream | match | 1 | 0 | — |
| `macos_tcp_flags.pcap` | JA4LS | per-stream | match | 1 | 0 | — |
| `macos_tcp_flags.pcap` | JA4T | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `macos_tcp_flags.pcap` | JA4TS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `macos_tcp_flags.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `macos_tcp_flags.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `quic-tls-handshake.pcapng` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-tls-handshake.pcapng` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-tls-handshake.pcapng` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-tls-handshake.pcapng` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-tls-handshake.pcapng` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-tls-handshake.pcapng` | JA4L | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-tls-handshake.pcapng` | JA4LS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-tls-handshake.pcapng` | JA4T | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-tls-handshake.pcapng` | JA4TS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-tls-handshake.pcapng` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-tls-handshake.pcapng` | JA4D6 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-with-several-tls-frames.pcapng` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-with-several-tls-frames.pcapng` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-with-several-tls-frames.pcapng` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-with-several-tls-frames.pcapng` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-with-several-tls-frames.pcapng` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-with-several-tls-frames.pcapng` | JA4L | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-with-several-tls-frames.pcapng` | JA4LS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-with-several-tls-frames.pcapng` | JA4T | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-with-several-tls-frames.pcapng` | JA4TS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-with-several-tls-frames.pcapng` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `quic-with-several-tls-frames.pcapng` | JA4D6 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the capture. |
| `single-packets.pcap` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `single-packets.pcap` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `single-packets.pcap` | JA4H | per-packet and per-stream | deviation | 29 | 11 | — |
| `single-packets.pcap` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `single-packets.pcap` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `single-packets.pcap` | JA4L | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `single-packets.pcap` | JA4LS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `single-packets.pcap` | JA4T | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `single-packets.pcap` | JA4TS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `single-packets.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `single-packets.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `socks-https-example.pcap` | JA4 | per-stream | match | 12 | 0 | — |
| `socks-https-example.pcap` | JA4S | per-packet and per-stream | match | 12 | 0 | — |
| `socks-https-example.pcap` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `socks-https-example.pcap` | JA4X | per-packet and per-stream | match | 18 | 0 | — |
| `socks-https-example.pcap` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `socks-https-example.pcap` | JA4L | per-packet and per-stream | deviation | 3 | 9 | — |
| `socks-https-example.pcap` | JA4LS | per-packet and per-stream | deviation | 3 | 6 | — |
| `socks-https-example.pcap` | JA4T | per-packet | match | 3 | 0 | — |
| `socks-https-example.pcap` | JA4TS | per-packet | match | 3 | 0 | — |
| `socks-https-example.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `socks-https-example.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `socks4-https.pcap` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `socks4-https.pcap` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `socks4-https.pcap` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `socks4-https.pcap` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `socks4-https.pcap` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `socks4-https.pcap` | JA4L | per-stream | match | 1 | 0 | — |
| `socks4-https.pcap` | JA4LS | per-stream | match | 1 | 0 | — |
| `socks4-https.pcap` | JA4T | per-packet | match | 1 | 0 | — |
| `socks4-https.pcap` | JA4TS | per-packet | match | 1 | 0 | — |
| `socks4-https.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `socks4-https.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `ssh-r.pcap` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh-r.pcap` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh-r.pcap` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh-r.pcap` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh-r.pcap` | JA4SSH | per-packet and per-stream | deviation | 13 | 6 | — |
| `ssh-r.pcap` | JA4L | per-packet and per-stream | deviation | 3 | 9 | — |
| `ssh-r.pcap` | JA4LS | per-packet and per-stream | deviation | 3 | 6 | — |
| `ssh-r.pcap` | JA4T | per-packet | match | 3 | 0 | — |
| `ssh-r.pcap` | JA4TS | per-packet | match | 3 | 0 | — |
| `ssh-r.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh-r.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `ssh-scp-1050.pcap` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh-scp-1050.pcap` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh-scp-1050.pcap` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh-scp-1050.pcap` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh-scp-1050.pcap` | JA4SSH | per-packet and per-stream | deviation | 6 | 3 | — |
| `ssh-scp-1050.pcap` | JA4L | per-packet and per-stream | deviation | 1 | 3 | — |
| `ssh-scp-1050.pcap` | JA4LS | per-packet and per-stream | deviation | 1 | 2 | — |
| `ssh-scp-1050.pcap` | JA4T | per-packet | match | 1 | 0 | — |
| `ssh-scp-1050.pcap` | JA4TS | per-packet | match | 1 | 0 | — |
| `ssh-scp-1050.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh-scp-1050.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `ssh.pcapng` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh.pcapng` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh.pcapng` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh.pcapng` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh.pcapng` | JA4SSH | per-packet and per-stream | deviation | 2 | 1 | — |
| `ssh.pcapng` | JA4L | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh.pcapng` | JA4LS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh.pcapng` | JA4T | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh.pcapng` | JA4TS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh.pcapng` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh.pcapng` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `ssh2-malformed.pcap` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh2-malformed.pcap` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh2-malformed.pcap` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh2-malformed.pcap` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh2-malformed.pcap` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh2-malformed.pcap` | JA4L | per-packet and per-stream | deviation | 1 | 3 | — |
| `ssh2-malformed.pcap` | JA4LS | per-packet and per-stream | deviation | 1 | 2 | — |
| `ssh2-malformed.pcap` | JA4T | per-packet | match | 1 | 0 | — |
| `ssh2-malformed.pcap` | JA4TS | per-packet | match | 1 | 0 | — |
| `ssh2-malformed.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh2-malformed.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `ssh2-moloch-crash.pcap` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh2-moloch-crash.pcap` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh2-moloch-crash.pcap` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh2-moloch-crash.pcap` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh2-moloch-crash.pcap` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh2-moloch-crash.pcap` | JA4L | per-packet and per-stream | deviation | 1 | 3 | — |
| `ssh2-moloch-crash.pcap` | JA4LS | per-packet and per-stream | deviation | 1 | 2 | — |
| `ssh2-moloch-crash.pcap` | JA4T | per-packet | match | 1 | 0 | — |
| `ssh2-moloch-crash.pcap` | JA4TS | per-packet | match | 1 | 0 | — |
| `ssh2-moloch-crash.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh2-moloch-crash.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `ssh2.pcapng` | JA4 | per-stream | deviation | 20 | 8 | — |
| `ssh2.pcapng` | JA4S | per-packet and per-stream | deviation | 16 | 8 | — |
| `ssh2.pcapng` | JA4H | per-packet and per-stream | deviation | 6 | 91 | — |
| `ssh2.pcapng` | JA4X | per-packet and per-stream | match | 36 | 0 | — |
| `ssh2.pcapng` | JA4SSH | per-packet and per-stream | deviation | 2 | 1 | — |
| `ssh2.pcapng` | JA4L | per-packet and per-stream | deviation | 9 | 22 | — |
| `ssh2.pcapng` | JA4LS | per-packet and per-stream | deviation | 9 | 17 | — |
| `ssh2.pcapng` | JA4T | per-packet | match | 75 | 0 | — |
| `ssh2.pcapng` | JA4TS | per-packet | match | 11 | 0 | — |
| `ssh2.pcapng` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `ssh2.pcapng` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `sshv1.pcap` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `sshv1.pcap` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `sshv1.pcap` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `sshv1.pcap` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `sshv1.pcap` | JA4SSH | per-packet | deviation | 0 | 4 | — |
| `sshv1.pcap` | JA4L | per-stream | match | 1 | 0 | — |
| `sshv1.pcap` | JA4LS | per-stream | match | 1 | 0 | — |
| `sshv1.pcap` | JA4T | per-packet | match | 1 | 0 | — |
| `sshv1.pcap` | JA4TS | per-packet | match | 1 | 0 | — |
| `sshv1.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `sshv1.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `tcpdump-geneve.pcap` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tcpdump-geneve.pcap` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tcpdump-geneve.pcap` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tcpdump-geneve.pcap` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tcpdump-geneve.pcap` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tcpdump-geneve.pcap` | JA4L | per-packet and per-stream | deviation | 1 | 3 | — |
| `tcpdump-geneve.pcap` | JA4LS | per-packet and per-stream | deviation | 1 | 2 | — |
| `tcpdump-geneve.pcap` | JA4T | per-packet | match | 1 | 0 | — |
| `tcpdump-geneve.pcap` | JA4TS | per-packet | match | 1 | 0 | — |
| `tcpdump-geneve.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tcpdump-geneve.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `tls-alpn-h2.pcap` | JA4 | per-stream | match | 4 | 0 | — |
| `tls-alpn-h2.pcap` | JA4S | per-packet and per-stream | match | 4 | 0 | — |
| `tls-alpn-h2.pcap` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-alpn-h2.pcap` | JA4X | per-packet and per-stream | match | 6 | 0 | — |
| `tls-alpn-h2.pcap` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-alpn-h2.pcap` | JA4L | per-stream | match | 1 | 0 | — |
| `tls-alpn-h2.pcap` | JA4LS | per-stream | match | 1 | 0 | — |
| `tls-alpn-h2.pcap` | JA4T | per-packet | match | 1 | 0 | — |
| `tls-alpn-h2.pcap` | JA4TS | per-packet | match | 1 | 0 | — |
| `tls-alpn-h2.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-alpn-h2.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `tls-handshake.pcapng` | JA4 | per-stream | deviation | 256 | 80 | — |
| `tls-handshake.pcapng` | JA4S | per-packet and per-stream | deviation | 282 | 52 | — |
| `tls-handshake.pcapng` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-handshake.pcapng` | JA4X | per-packet and per-stream | match | 42 | 0 | — |
| `tls-handshake.pcapng` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-handshake.pcapng` | JA4L | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-handshake.pcapng` | JA4LS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-handshake.pcapng` | JA4T | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-handshake.pcapng` | JA4TS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-handshake.pcapng` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-handshake.pcapng` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `tls-non-ascii-alpn.pcapng` | JA4 | per-stream | match | 4 | 0 | — |
| `tls-non-ascii-alpn.pcapng` | JA4S | per-packet and per-stream | match | 4 | 0 | — |
| `tls-non-ascii-alpn.pcapng` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-non-ascii-alpn.pcapng` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-non-ascii-alpn.pcapng` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-non-ascii-alpn.pcapng` | JA4L | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-non-ascii-alpn.pcapng` | JA4LS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-non-ascii-alpn.pcapng` | JA4T | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-non-ascii-alpn.pcapng` | JA4TS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-non-ascii-alpn.pcapng` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-non-ascii-alpn.pcapng` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `tls-sni.pcapng` | JA4 | per-stream | deviation | 256 | 80 | — |
| `tls-sni.pcapng` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-sni.pcapng` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-sni.pcapng` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-sni.pcapng` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-sni.pcapng` | JA4L | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-sni.pcapng` | JA4LS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-sni.pcapng` | JA4T | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-sni.pcapng` | JA4TS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-sni.pcapng` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls-sni.pcapng` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `tls12.pcap` | JA4 | per-stream | match | 4 | 0 | — |
| `tls12.pcap` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls12.pcap` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls12.pcap` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls12.pcap` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls12.pcap` | JA4L | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls12.pcap` | JA4LS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls12.pcap` | JA4T | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls12.pcap` | JA4TS | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls12.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls12.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `tls3.pcapng` | JA4 | per-stream | deviation | 28 | 24 | — |
| `tls3.pcapng` | JA4S | per-packet and per-stream | deviation | 40 | 12 | — |
| `tls3.pcapng` | JA4H | per-packet and per-stream | deviation | 3 | 14 | — |
| `tls3.pcapng` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls3.pcapng` | JA4SSH | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls3.pcapng` | JA4L | per-packet and per-stream | deviation | 9 | 32 | — |
| `tls3.pcapng` | JA4LS | per-packet and per-stream | deviation | 13 | 22 | — |
| `tls3.pcapng` | JA4T | per-packet | match | 8 | 0 | — |
| `tls3.pcapng` | JA4TS | per-packet | match | 8 | 0 | — |
| `tls3.pcapng` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `tls3.pcapng` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
| `v6.pcap` | JA4 | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `v6.pcap` | JA4S | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `v6.pcap` | JA4H | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `v6.pcap` | JA4X | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `v6.pcap` | JA4SSH | per-packet | deviation | 0 | 4 | — |
| `v6.pcap` | JA4L | per-stream | match | 1 | 0 | — |
| `v6.pcap` | JA4LS | per-stream | match | 1 | 0 | — |
| `v6.pcap` | JA4T | per-packet | match | 1 | 0 | — |
| `v6.pcap` | JA4TS | per-packet | match | 1 | 0 | — |
| `v6.pcap` | JA4D | — | not applicable | 0 | 0 | No vector of the corpus holds a value for the method on the capture. |
| `v6.pcap` | JA4D6 | — | not applicable | 0 | 0 | FoxIO writes JA4D and JA4D6 under the single field `ja4.ja4d`, and FR-conformance-25 compares the two under JA4D. |
