| variant | m MiB | blocks | residue addresses | distinct blocks found | tag hits | KDF ms | scanned MiB |
|---|---|---|---|---|---|---|---|
| positive-control-leak | 64 | 65536 | 65536 | 65536 | 2 | 117 | 72 |
| lib-default | 64 | 65536 | 0 | 0 | 2 | 130 | 8 |
| own-nozero | 64 | 65536 | 0 | 0 | 2 | 116 | 8 |
| own-zeroizing | 64 | 65536 | 0 | 0 | 2 | 136 | 8 |
| own-zeroizing-scrub | 64 | 65536 | 0 | 0 | 0 | 116 | 8 |
| thread-zeroizing-scrub | 64 | 65536 | 0 | 0 | 0 | 114 | 10 |
| positive-control-leak | 0 | 64 | 64 | 64 | 2 | 0 | 3 |
| lib-default | 0 | 64 | 61 | 61 | 2 | 0 | 3 |
| own-nozero | 0 | 64 | 61 | 61 | 2 | 0 | 3 |
| own-zeroizing | 0 | 64 | 0 | 0 | 2 | 0 | 3 |
| own-zeroizing-scrub | 0 | 64 | 0 | 0 | 0 | 0 | 3 |
| thread-zeroizing-scrub | 0 | 64 | 0 | 0 | 0 | 0 | 5 |
