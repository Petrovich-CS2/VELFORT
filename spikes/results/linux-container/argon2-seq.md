background load threads: 0, own-buffer: false
argon2 crate 0.6.0, parallel feature: false
available_parallelism: Ok(4)
KAT RFC 9106 §5.3 Argon2id: OK
| m (MiB) | t | p | runs | min ms | median ms | max ms | peak WS/RSS MiB (process, cumulative) |
|---|---|---|---|---|---|---|---|
| 64 | 3 | 4 | 5 | 97 | 113 | 119 | 66 |
| 128 | 3 | 4 | 5 | 221 | 239 | 293 | 130 |
| 256 | 3 | 4 | 5 | 574 | 583 | 606 | 258 |
| 512 | 3 | 4 | 5 | 1061 | 1081 | 1178 | 514 |
| 256 | 2 | 4 | 5 | 351 | 355 | 372 | 258 |
| 1024 | 1 | 4 | 5 | 939 | 1001 | 1108 | 1026 |
| 19 | 2 | 1 | 5 | 15 | 18 | 19 | 21 |

under 4 busy threads:
| 64 | 3 | 4 | 5 | 100 | 102 | 168 | 66 |
| 256 | 3 | 4 | 5 | 602 | 612 | 661 | 258 |
