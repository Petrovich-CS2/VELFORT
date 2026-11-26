background load threads: 0, own-buffer: false
argon2 crate 0.6.0, parallel feature: true
available_parallelism: Ok(4)
KAT RFC 9106 §5.3 Argon2id: OK
| m (MiB) | t | p | runs | min ms | median ms | max ms | peak WS/RSS MiB (process, cumulative) |
|---|---|---|---|---|---|---|---|
| 64 | 3 | 4 | 5 | 48 | 49 | 51 | 66 |
| 128 | 3 | 4 | 5 | 110 | 115 | 140 | 130 |
| 256 | 3 | 4 | 5 | 215 | 231 | 232 | 258 |
| 512 | 3 | 4 | 5 | 461 | 465 | 490 | 514 |
| 256 | 2 | 4 | 5 | 178 | 181 | 187 | 258 |
| 1024 | 1 | 4 | 5 | 594 | 624 | 652 | 1026 |
| 19 | 2 | 1 | 5 | 17 | 17 | 22 | 22 |

under 4 busy threads:
| 64 | 3 | 4 | 5 | 152 | 160 | 179 | 66 |
| 256 | 3 | 4 | 5 | 485 | 555 | 606 | 259 |
