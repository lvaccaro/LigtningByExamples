Lightning by Examples
===

**WARNING - Early-stage software, do not use with real bitcoins.**

This repository contains a series of rudimental examples to learn the bitcoin & ligthning world with rust.

I'm no rust expert, so I'm learning too.

It is based on:
  * [BitcoinD](https://github.com/rcasatta/bitcoind)
  * [LightningD](https://github.com/rcasatta/ligthningd)
  * [clightningrpc](https://github.com/laanwj/cln4rust)

### Submarine swap
Swap onchain BTC to lightning BTC, with HTLC.
```
cargo run --bin submarineswap
```

### Reverse submarine swap
Swap lightning BTC to onchain BTC, with an HTLC (without hold invoice).
```
cargo run --bin reverseswap
```
