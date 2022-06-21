# PPENC

Status: Alpha

PPEnc is an encryption library targetting 16 bit microcontrollers which wish to send data over a network.
It is written in C89 and no dependencies other than a required stdint header.
The required types are `uint8_t`, `uint16_t` and `uint32_t`.

It is designed to be very small (both code and buffers).

## Building and Testing

The test suite is written in Rust.
First obtain a copy of the [Rust toolchain](https://www.rust-lang.org/tools/install),
then

```
  cargo test
```

NOTE: To be clear - this is *NOT* a `no_std` rust crate.

### Defines

```
  -DINLINE=inline
```

This define is required.
C89 does not include the inline keyword - you may also set INLINE="" if
lacking support or to decrease binary size.

```
   -DSTATIC=static
```

This define is required.
You may set STATIC to either static or "".
By design we only set STATIC to "" in order to run the test suite.

```
  -DPPENC_64
```

This define is optional.
Build a 64bit version (requires uint64_t).
