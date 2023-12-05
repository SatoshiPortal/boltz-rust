# bullbitcoin-rnd

A bitcoin rnd repo, currently using:

- bdk
- boltz.exchange

# test

```bash
cargo test -- --nocapture
```

`test_*_swap` is ignored by default, always push commits with them ignored. 

To run `test_normal_swap`, make sure to upadate the `invoice`.

`swapstatus` is tested within `test_*_swap`, however a separate test exists to manually test your swap' status through its lifetime.

This is also ignored, to run it, make sure you update the `id` accordingly.