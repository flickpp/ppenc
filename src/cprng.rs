#[cfg(test)]
mod tests {
    use chacha::KeyStream;
    use random_fast_rng::{FastRng, Random};

    #[derive(Default)]
    #[repr(C)]
    struct ChaCha8 {
        key: [u32; 8],
        nonce: [u32; 2],
        block: [u16; 32],
        counter: u32,
        pos: u8,
    }
    extern "C" {
        fn ppenc_chacha8_init(chacha8: *mut ChaCha8, key: *const u8, nonce: *const u8);
        fn ppenc_chacha8_nbytes(chacha8: *mut ChaCha8, dst: *mut u8, num_bytes: u16);
    }

    #[test]
    fn chacha8_known_value() {
        let key = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x00,
        ];
        let nonce = [0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78];
        let mut c8 = ChaCha8::default();

        unsafe {
            ppenc_chacha8_init(&mut c8, key.as_ptr(), nonce.as_ptr());
        }

        let mut output = vec![0; 64];
        unsafe {
            ppenc_chacha8_nbytes(&mut c8, output.as_mut_ptr(), 64);
        }

        assert_eq!(
            &output,
            &[
                0xdb, 0x43, 0xad, 0x9d, 0x1e, 0x84, 0x2d, 0x12, 0x72, 0xe4, 0x53, 0x0e, 0x27, 0x6b,
                0x3f, 0x56, 0x8f, 0x88, 0x59, 0xb3, 0xf7, 0xcf, 0x6d, 0x9d, 0x2c, 0x74, 0xfa, 0x53,
                0x80, 0x8c, 0xb5, 0x15, 0x7a, 0x8e, 0xbf, 0x46, 0xad, 0x3d, 0xcc, 0x4b, 0x6c, 0x7d,
                0xad, 0xde, 0x13, 0x17, 0x84, 0xb0, 0x12, 0x0e, 0x0e, 0x22, 0xf6, 0xd5, 0xf9, 0xff,
                0xa7, 0x40, 0x7d, 0x4a, 0x21, 0xb6, 0x95, 0xd9,
            ]
        );
    }

    #[test]
    fn chacha8_rand() {
        let mut rng = FastRng::new();
        let mut c8 = ChaCha8::default();
        let key = rng.gen::<[u8; 32]>();
        let nonce = rng.gen::<[u8; 8]>();

        unsafe {
            ppenc_chacha8_init(&mut c8, key.as_ptr(), nonce.as_ptr());
        }

        let mut other_c8 = chacha::ChaCha::new_chacha8(&key, &nonce);

        for num_bytes in [1, 5, 31, 32, 33, 63, 64, 65] {
            let mut bytes = Vec::with_capacity(num_bytes);
            bytes.resize(num_bytes, 0);
            unsafe {
                ppenc_chacha8_nbytes(&mut c8, bytes.as_mut_ptr(), num_bytes as u16);
            }

            println!("{:?}", bytes);

            other_c8
                .xor_read(&mut bytes)
                .expect("couldn't xor_read from chacha8");

            println!("{:?}", bytes);

            for b in bytes {
                assert!(b == 0)
            }
        }
    }
}
