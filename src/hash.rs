#[cfg(test)]
mod tests {
    use hmac_sha256::Hash as Sha256;
    use random_fast_rng::{FastRng, Random};
    extern "C" {
        fn cubehash_rounds(state: *mut u32, num_rounds: u16);
        fn ppenc_sha256_len48(hash_value: *mut u8, msg: *const u8, message_schedule_buf: *mut u32);
        //       fn ppenc_cubehash(hash_value: *mut u8, msg: *mut u8, msg_len: u32);
    }

    #[test]
    fn sha256_len48() {
        let mut rng = FastRng::new();
        let msg = rng.gen::<[u8; 48]>();
        let mut message_schedule_buf = [0; 256];
        let mut hash_value = [0; 32];
        let mut buf64 = Vec::with_capacity(64);

        let mut hasher = Sha256::new();
        hasher.update(&msg);
        let ans = hasher.finalize();

        buf64.extend(&msg);
        buf64.resize(64, 0);

        unsafe {
            ppenc_sha256_len48(
                hash_value.as_mut_ptr(),
                buf64.as_ptr(),
                message_schedule_buf.as_mut_ptr(),
            );
        }

        assert_eq!(ans, hash_value);
    }

    #[test]
    fn cubehash_rounds_() {
        let mut state = [0; 32];
        state[0] = 64;
        state[1] = 32;
        state[2] = 16;
        unsafe {
            cubehash_rounds(state.as_mut_ptr(), 16);
        }

        assert_eq!(
            state,
            [
                0x781f814f, 0x18f45926, 0x992b7520, 0xc8237df7, 0xe4e3ba88, 0x7b0075ff, 0x51916982,
                0x947c6147, 0x9dc06f0a, 0x4d197eb5, 0xb6e17224, 0x912e1aca, 0x5270f5e1, 0xd9efd0ec,
                0xf0fcf7c8, 0x20d4074f, 0x15547fee, 0xf4839313, 0x17c189c, 0xaf1c332a, 0xde4d7c8c,
                0x84997eec, 0x5bd87a43, 0xb6d3d055, 0x3ae247b0, 0x2b8cb0a6, 0xd9d6ca35, 0x4bf12b94,
                0x97f33a51, 0x62fb84ad, 0x7e70e613, 0x520c709b,
            ]
        );
    }

    #[test]
    fn cubehash() {
        /* TODO */
    }
}
