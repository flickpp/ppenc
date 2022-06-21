#[cfg(test)]
mod tests {
    use random_fast_rng::{FastRng, Random};

    #[derive(Default, PartialEq, Eq, Debug)]
    #[repr(C)]
    struct ThreeFishSubKeys64 {
        _0: u64,
        _1: u64,
        _2: u64,
        _3: u64,
        _4: u64,
        _5: u64,
        _6: u64,
        _7: u64,
    }

    #[derive(Default)]
    #[repr(C)]
    struct ThreeFishBuffer64 {
        subkeys: [ThreeFishSubKeys64; 19],
        tweaks: [u32; 6],
        keys: [u64; 9],
    }

    extern "C" {
        fn sixty4_add_inplace(lhs: *mut u32, rhs_lower: u32, rhs_upper: u32);
        fn sixty4_sub_inplace(lhs: *mut u32, rhs_lower: u32, rhs_upper: u32);
        fn sixty4_rotleft_inplace(lhs: *mut u32, amount: u8);
        fn sixty4_rotright_inplace(lhs: *mut u32, amount: u8);

        // PCG32
        fn pcg32_64bit(inc: u32, state: *mut u64) -> u32;
        fn pcg32(inc: u32, state: *mut u32) -> u32;

        // threefish
        fn threefish_buf_init(buf3f: *mut u8, body_key: *const u8, pcg32_state: *mut u32);
        fn threefish_encrypt_block(buf3f: *const u8, block: *mut u32, block_alt: *mut u8);
        fn threefish_decrypt_block(buf3f: *const u8, block: *mut u32, block_alt: *mut u8);

        fn threefish_buf_init_64bit(
            buf3f: *mut ThreeFishBuffer64,
            body_key: *const u8,
            pcg32_state: *mut u64,
        );
        fn threefish_encrypt_block_64bit(
            buf3f: *const ThreeFishBuffer64,
            block: *mut u64,
            block_alt: *mut u8,
        );
        fn threefish_decrypt_block_64bit(
            buf3f: *const ThreeFishBuffer64,
            block: *mut u64,
            block_alt: *mut u8,
        );

        fn ppenc_threefish512_encrypt_64bit(
            key: *const u8,
            tweek_seed: *const u8,
            body: *mut u8,
            num_blocks: u32,
            buf3f: *mut ThreeFishBuffer64,
            buf64: *mut u8,
        );

        fn ppenc_threefish512_encrypt(
            key: *const u8,
            tweek_seed: *const u8,
            body: *mut u8,
            num_blocks: u32,
            buf3f: *mut u8,
            buf64: *mut u8,
        );

        fn ppenc_threefish512_decrypt_64bit(
            key: *const u8,
            tweek_seed: *const u8,
            body: *mut u8,
            num_blocks: u32,
            buf3f: *mut ThreeFishBuffer64,
            buf64: *mut u8,
        );

        fn ppenc_threefish512_decrypt(
            key: *const u8,
            tweek_seed: *const u8,
            body: *mut u8,
            num_blocks: u32,
            buf3f: *mut u8,
            buf64: *mut u8,
        );
    }
    fn new64(val: &[u32; 2]) -> u64 {
        let mut ans: u64 = val[1] as u64;
        ans <<= 32;
        ans += val[0] as u64;
        ans
    }

    fn build_cases() -> Vec<[u32; 2]> {
        let mut rng = FastRng::new();
        let nums: [u32; 8] = [
            0,
            1,
            2,
            0xffffffff,
            0xfffffffe,
            0xefffffff,
            rng.gen(),
            rng.gen(),
        ];
        let mut cases = vec![];
        for &n in nums.iter() {
            for &n2 in nums.iter() {
                cases.push([n, n2]);
            }
        }

        cases
    }

    fn block_to_u64(block: &[u8; 64]) -> Vec<u64> {
        let mut v = Vec::with_capacity(8);
        for i in 0..8 {
            let j = i * 8;
            v.push(u64::from_le_bytes([
                block[j],
                block[j + 1],
                block[j + 2],
                block[j + 3],
                block[j + 4],
                block[j + 5],
                block[j + 6],
                block[j + 7],
            ]));
        }

        v
    }

    fn vec64_to_block(v: &[u64]) -> [u8; 64] {
        let mut ans = [0; 64];

        for (n, b) in v.iter().enumerate() {
            let i = n * 8;
            let b = b.to_le_bytes();
            for j in 0..8 {
                ans[i + j] = b[j];
            }
        }

        ans
    }

    fn block_to_u32(block: &[u8; 64]) -> Vec<u32> {
        let mut v = Vec::with_capacity(8);
        for i in 0..16 {
            let j = i * 4;
            v.push(u32::from_le_bytes([
                block[j],
                block[j + 1],
                block[j + 2],
                block[j + 3],
            ]));
        }

        v
    }

    fn vec32_to_block(v: &[u32]) -> [u8; 64] {
        let mut ans = [0; 64];

        for (n, b) in v.iter().enumerate() {
            let i = n * 4;
            let b = b.to_le_bytes();
            for j in 0..4 {
                ans[i + j] = b[j];
            }
        }

        ans
    }

    #[test]
    fn _sixty4_add_inplace() {
        let cases = build_cases();

        for lhs in cases.iter() {
            for rhs in cases.iter() {
                let mut lhs = lhs.to_owned();
                let rhs64 = new64(rhs);
                let lhs64 = new64(&lhs);

                unsafe {
                    sixty4_add_inplace(lhs.as_mut_ptr(), rhs[0], rhs[1]);
                }

                assert_eq!(new64(&lhs), lhs64.wrapping_add(rhs64));
            }
        }
    }

    #[test]
    fn _sixty4_sub_inplace() {
        let cases = build_cases();
        for lhs in cases.iter() {
            for rhs in cases.iter() {
                let mut lhs2 = lhs.to_owned();

                unsafe {
                    sixty4_sub_inplace(lhs2.as_mut_ptr(), rhs[0], rhs[1]);
                }

                unsafe { sixty4_add_inplace(lhs2.as_mut_ptr(), rhs[0], rhs[1]) }

                assert_eq!(&lhs2, lhs);
            }
        }
    }

    #[test]
    fn _sixty4_rotleft_inplace() {
        let cases = build_cases();

        for lhs in cases.iter() {
            for r in [1, 2, 30, 31] {
                let mut lhs2 = lhs.to_owned();
                unsafe {
                    sixty4_rotleft_inplace(lhs2.as_mut_ptr(), r);
                }

                assert_eq!(new64(&lhs2), new64(lhs).rotate_left(r as u32));
            }
        }
    }

    #[test]
    fn _sixty4_rotright_inplace() {
        let cases = build_cases();

        for lhs in cases.iter() {
            for r in [1, 2, 30, 31] {
                let mut lhs2 = lhs.to_owned();
                unsafe {
                    sixty4_rotright_inplace(lhs2.as_mut_ptr(), r);
                }

                assert_eq!(new64(&lhs2), new64(lhs).rotate_right(r as u32));
            }
        }
    }

    #[test]
    fn pcg32_known_value() {
        let mut state: [u32; 2] = [0xfc1c7860, 0x4c0c30ef];
        let ans = unsafe { pcg32(5, state.as_mut_ptr()) };
        assert_eq!(3477127742, ans);
        assert_eq!(state, [0x0098c8e5, 0xaf0e8170]);
    }

    #[test]
    fn pcg32_known_value64() {
        let mut state: u64 = 0x4c0c30effc1c7860;
        let ans = unsafe { pcg32_64bit(5, &mut state) };
        assert_eq!(3477127742, ans);
        assert_eq!(state, 12614161924357671141);
    }

    #[test]
    fn pcg32_same_value() {
        let mut rng = FastRng::new();
        let state = rng.gen::<[u8; 8]>();
        let mut state64 = u64::from_le_bytes(state.clone());
        let mut state32 = [
            u32::from_le_bytes([state[0], state[1], state[2], state[3]]),
            u32::from_le_bytes([state[4], state[5], state[6], state[7]]),
        ];

        let inc: u32 = rng.gen();

        assert_eq!(unsafe { pcg32(inc, state32.as_mut_ptr()) }, unsafe {
            pcg32_64bit(inc, &mut state64)
        });

        let mut state8 = Vec::with_capacity(8);
        state8.extend(state32[0].to_le_bytes());
        state8.extend(state32[1].to_le_bytes());

        assert_eq!(&state64.to_le_bytes()[..], state8);
    }

    /*
        #[test]
        fn threefish_buffer_init64() {
            let mut rng = FastRng::new();
            let key = rng.gen::<[u8; 64]>();
            let mut buf3f = ThreeFishBuffer64::default();
            let mut state: u64 = rng.gen();

            unsafe {
                threefish_buf_init_64bit(&mut buf3f, key.as_ptr(), &mut state);
            }

            let mut keys = Vec::with_capacity(9);
            for i in 0..8 {
                let j = i * 8;
                keys.push(u64::from_le_bytes([
                    key[j],
                    key[j + 1],
                    key[j + 2],
                    key[j + 3],
                    key[j + 4],
                    key[j + 5],
                    key[j + 6],
                    key[j + 7],
                ]));
            }
            keys.push(0x1BD11BDAA9FC1A22);
            for k in (&keys[..8]).to_owned() {
                keys[8] ^= k;
            }

            for (k1, k2) in keys.iter().zip(buf3f.keys.iter()) {
                assert_eq!(k1, k2);
            }

            let mut tweaks: [u64; 3] = [0; 3];
            tweaks[0] = u64::from_le_bytes([
                tweak[0], tweak[1], tweak[2], tweak[3], tweak[4], tweak[5], tweak[6], tweak[7],
            ]);
            tweaks[1] = u64::from_le_bytes([
                tweak[8], tweak[9], tweak[10], tweak[11], tweak[12], tweak[13], tweak[14], tweak[15],
            ]);
            tweaks[2] = tweaks[0] ^ tweaks[1];

            for s in 0..=18 {
                let subkey = ThreeFishSubKeys64 {
                    _0: keys[s % 9],
                    _1: keys[(s + 1) % 9],
                    _2: keys[(s + 2) % 9],
                    _3: keys[(s + 3) % 9],
                    _4: keys[(s + 4) % 9],
                    _5: keys[(s + 5) % 9].wrapping_add(tweaks[s % 3]),
                    _6: keys[(s + 6) % 9].wrapping_add(tweaks[(s + 1) % 3]),
                    _7: keys[(s + 7) % 9].wrapping_add(s as u64),
                };

                assert_eq!(subkey, buf3f.subkeys[s]);
            }
    }
        */

    #[test]
    fn threefish_encrypt_known_value32() {
        let mut buf3f = vec![0; 1312];

        let block = [
            45, 51, 56, 0, 251, 43, 138, 54, 211, 193, 146, 33, 255, 145, 166, 123, 247, 144, 250,
            237, 129, 112, 98, 65, 235, 226, 14, 20, 153, 51, 62, 23, 206, 120, 192, 225, 19, 102,
            207, 208, 91, 209, 73, 88, 9, 152, 133, 119, 189, 52, 170, 184, 125, 211, 104, 96, 212,
            174, 17, 48, 151, 78, 195, 135,
        ];

        let key = [
            65, 122, 108, 234, 127, 39, 212, 137, 176, 128, 82, 155, 92, 68, 165, 100, 90, 213, 56,
            96, 30, 130, 84, 123, 26, 92, 51, 231, 115, 44, 183, 88, 221, 186, 111, 245, 230, 33,
            51, 19, 1, 227, 135, 211, 108, 237, 110, 186, 1, 31, 250, 211, 126, 210, 149, 211, 138,
            0, 75, 150, 138, 235, 59, 132,
        ];

        let mut state = [0x1fcc33ac, 0x4777629f];

        unsafe {
            threefish_buf_init(buf3f.as_mut_ptr(), key.as_ptr(), state.as_mut_ptr());
        }

        let mut block32 = block_to_u32(&block);
        let mut block_alt = [0; 64];

        unsafe {
            threefish_encrypt_block(buf3f.as_ptr(), block32.as_mut_ptr(), block_alt.as_mut_ptr());
        }

        assert_eq!(
            vec32_to_block(&block32),
            [
                222, 22, 127, 66, 131, 101, 99, 58, 104, 111, 243, 29, 88, 148, 218, 208, 150, 19,
                222, 173, 221, 250, 54, 5, 65, 45, 16, 115, 123, 213, 223, 8, 246, 128, 122, 31,
                113, 42, 192, 133, 64, 37, 193, 61, 218, 126, 132, 41, 203, 84, 19, 89, 103, 219,
                138, 213, 29, 203, 117, 228, 137, 236, 228, 55,
            ],
        );
    }

    #[test]
    fn threefish_encrypt_known_value64() {
        let mut buf3f = ThreeFishBuffer64::default();
        let mut state: u64 = 0x4c0c30effc1c7860;

        let block = [
            45, 51, 56, 0, 251, 43, 138, 54, 211, 193, 146, 33, 255, 145, 166, 123, 247, 144, 250,
            237, 129, 112, 98, 65, 235, 226, 14, 20, 153, 51, 62, 23, 206, 120, 192, 225, 19, 102,
            207, 208, 91, 209, 73, 88, 9, 152, 133, 119, 189, 52, 170, 184, 125, 211, 104, 96, 212,
            174, 17, 48, 151, 78, 195, 135,
        ];

        let key = [
            65, 122, 108, 234, 127, 39, 212, 137, 176, 128, 82, 155, 92, 68, 165, 100, 90, 213, 56,
            96, 30, 130, 84, 123, 26, 92, 51, 231, 115, 44, 183, 88, 221, 186, 111, 245, 230, 33,
            51, 19, 1, 227, 135, 211, 108, 237, 110, 186, 1, 31, 250, 211, 126, 210, 149, 211, 138,
            0, 75, 150, 138, 235, 59, 132,
        ];

        unsafe {
            threefish_buf_init_64bit(&mut buf3f, key.as_ptr(), &mut state);
        }

        let mut block64 = block_to_u64(&block);
        let mut block_alt = [0; 64];

        unsafe {
            threefish_encrypt_block_64bit(&buf3f, block64.as_mut_ptr(), block_alt.as_mut_ptr());
        }

        assert_eq!(
            vec64_to_block(&block64),
            [
                220, 147, 126, 145, 206, 55, 65, 197, 146, 120, 33, 162, 122, 223, 228, 44, 255,
                153, 198, 25, 225, 61, 89, 21, 114, 128, 134, 91, 5, 163, 29, 252, 59, 118, 220,
                31, 221, 174, 131, 100, 180, 208, 192, 102, 161, 132, 8, 249, 28, 89, 202, 223, 58,
                134, 71, 85, 187, 237, 194, 5, 8, 254, 160, 97,
            ],
        );
    }

    #[test]
    fn threefish_encrypt_32_64_same_value() {
        let mut rng = FastRng::new();
        let mut buf3f_32 = [0u8; 1312];
        let mut buf3f_64 = ThreeFishBuffer64::default();
        let block = rng.gen::<[u8; 64]>();
        let key = rng.gen::<[u8; 64]>();
        let mut state64: u64 = rng.gen();
        let mut state32 = {
            let i = state64.to_le_bytes();
            [
                u32::from_le_bytes([i[0], i[1], i[2], i[3]]),
                u32::from_le_bytes([i[4], i[5], i[6], i[7]]),
            ]
        };

        unsafe {
            threefish_buf_init(buf3f_32.as_mut_ptr(), key.as_ptr(), state32.as_mut_ptr());
            threefish_buf_init_64bit(&mut buf3f_64, key.as_ptr(), &mut state64);
        }

        let mut block_32 = block_to_u32(&block);
        let mut block_64 = block_to_u64(&block);

        unsafe {
            let mut block_alt = [0; 64];
            threefish_encrypt_block(
                buf3f_32.as_ptr(),
                block_32.as_mut_ptr(),
                block_alt.as_mut_ptr(),
            );
            threefish_encrypt_block_64bit(&buf3f_64, block_64.as_mut_ptr(), block_alt.as_mut_ptr());
        }

        assert_eq!(vec32_to_block(&block_32), vec64_to_block(&block_64));
    }

    #[test]
    fn threefish_decrypt_32_64_same_value() {
        let mut rng = FastRng::new();
        let mut buf3f_32 = [0u8; 1312];
        let mut buf3f_64 = ThreeFishBuffer64::default();
        let block = rng.gen::<[u8; 64]>();
        let key = rng.gen::<[u8; 64]>();
        let mut state64: u64 = rng.gen();
        let mut state32 = {
            let i = state64.to_le_bytes();
            [
                u32::from_le_bytes([i[0], i[1], i[2], i[3]]),
                u32::from_le_bytes([i[4], i[5], i[6], i[7]]),
            ]
        };

        unsafe {
            threefish_buf_init(buf3f_32.as_mut_ptr(), key.as_ptr(), state32.as_mut_ptr());
            threefish_buf_init_64bit(&mut buf3f_64, key.as_ptr(), &mut state64);
        }

        let mut block_32 = block_to_u32(&block);
        let mut block_64 = block_to_u64(&block);

        unsafe {
            let mut block_alt = [0; 64];
            threefish_decrypt_block(
                buf3f_32.as_ptr(),
                block_32.as_mut_ptr(),
                block_alt.as_mut_ptr(),
            );
            threefish_decrypt_block_64bit(&buf3f_64, block_64.as_mut_ptr(), block_alt.as_mut_ptr());
        }

        assert_eq!(vec32_to_block(&block_32), vec64_to_block(&block_64));
    }

    #[test]
    fn threefish_decrypt_block_known_value32() {
        let mut buf3f = [0; 1312];
        let block = [
            121, 125, 169, 193, 133, 217, 193, 88, 153, 76, 23, 216, 221, 134, 153, 199, 98, 123,
            14, 104, 50, 64, 165, 224, 235, 99, 175, 80, 43, 97, 187, 187, 32, 163, 30, 92, 230,
            163, 148, 65, 46, 199, 36, 108, 230, 235, 203, 249, 160, 199, 238, 136, 219, 145, 24,
            144, 21, 24, 237, 79, 12, 220, 152, 200,
        ];

        let key = [
            192, 73, 229, 44, 148, 105, 180, 224, 183, 30, 179, 201, 52, 41, 214, 34, 200, 162, 23,
            53, 249, 14, 155, 39, 5, 31, 34, 243, 66, 169, 222, 117, 11, 25, 77, 159, 110, 109,
            112, 179, 75, 193, 142, 64, 67, 167, 196, 77, 203, 232, 131, 251, 66, 100, 81, 119,
            254, 76, 140, 60, 37, 141, 63, 36,
        ];

        let mut state = [0x5733ffec, 0xfaad6ea0];

        unsafe {
            threefish_buf_init(buf3f.as_mut_ptr(), key.as_ptr(), state.as_mut_ptr());
        }

        let mut block_32 = block_to_u32(&block);

        unsafe {
            let mut block_alt = [0; 64];
            threefish_decrypt_block(
                buf3f.as_ptr(),
                block_32.as_mut_ptr(),
                block_alt.as_mut_ptr(),
            );
        }

        assert_eq!(
            vec32_to_block(&block_32),
            [
                141, 245, 58, 165, 182, 254, 210, 120, 115, 50, 67, 229, 30, 116, 158, 218, 165,
                195, 240, 197, 141, 119, 231, 11, 119, 172, 183, 187, 30, 173, 37, 19, 200, 221,
                237, 117, 46, 82, 197, 237, 105, 191, 248, 13, 207, 1, 137, 94, 153, 148, 216, 54,
                92, 142, 189, 234, 70, 185, 100, 166, 218, 71, 115, 42,
            ],
        );
    }

    #[test]
    fn threefish_decrypt_block_known_value64() {
        let mut buf3f = ThreeFishBuffer64::default();
        let block = [
            121, 125, 169, 193, 133, 217, 193, 88, 153, 76, 23, 216, 221, 134, 153, 199, 98, 123,
            14, 104, 50, 64, 165, 224, 235, 99, 175, 80, 43, 97, 187, 187, 32, 163, 30, 92, 230,
            163, 148, 65, 46, 199, 36, 108, 230, 235, 203, 249, 160, 199, 238, 136, 219, 145, 24,
            144, 21, 24, 237, 79, 12, 220, 152, 200,
        ];

        let key = [
            192, 73, 229, 44, 148, 105, 180, 224, 183, 30, 179, 201, 52, 41, 214, 34, 200, 162, 23,
            53, 249, 14, 155, 39, 5, 31, 34, 243, 66, 169, 222, 117, 11, 25, 77, 159, 110, 109,
            112, 179, 75, 193, 142, 64, 67, 167, 196, 77, 203, 232, 131, 251, 66, 100, 81, 119,
            254, 76, 140, 60, 37, 141, 63, 36,
        ];

        let mut state: u64 = 0xd44e3fdbe65a85bc;

        unsafe {
            threefish_buf_init_64bit(&mut buf3f, key.as_ptr(), &mut state);
        }

        let mut block_64 = block_to_u64(&block);

        unsafe {
            let mut block_alt = [0; 64];
            threefish_decrypt_block_64bit(&buf3f, block_64.as_mut_ptr(), block_alt.as_mut_ptr());
        }

        assert_eq!(
            vec64_to_block(&block_64),
            [
                236, 238, 56, 32, 117, 13, 19, 17, 24, 126, 204, 130, 126, 119, 51, 23, 194, 124,
                126, 167, 101, 219, 148, 120, 142, 33, 41, 113, 226, 152, 229, 25, 84, 45, 242,
                244, 62, 94, 59, 21, 185, 51, 44, 7, 168, 3, 253, 159, 223, 119, 247, 107, 97, 223,
                92, 80, 18, 215, 61, 248, 39, 102, 17, 133,
            ],
        );
    }

    #[test]
    fn threefish_encrypt32_decrypt64() {
        let mut rng = FastRng::new();
        let key = rng.gen::<[u8; 64]>();
        let block = rng.gen::<[u8; 64]>();
        let mut buf3f_32 = [0; 1312];
        let mut buf3f_64 = ThreeFishBuffer64::default();
        let mut block_alt = [0; 64];
        let mut state64: u64 = rng.gen();
        let mut state32 = {
            let i = state64.to_le_bytes();
            [
                u32::from_le_bytes([i[0], i[1], i[2], i[3]]),
                u32::from_le_bytes([i[4], i[5], i[6], i[7]]),
            ]
        };

        unsafe {
            threefish_buf_init(buf3f_32.as_mut_ptr(), key.as_ptr(), state32.as_mut_ptr());
            threefish_buf_init_64bit(&mut buf3f_64, key.as_ptr(), &mut state64);
        }

        let mut block_32 = block_to_u32(&block);
        unsafe {
            threefish_encrypt_block(
                buf3f_32.as_ptr(),
                block_32.as_mut_ptr(),
                block_alt.as_mut_ptr(),
            );
        }

        let enc_block = vec32_to_block(&block_32);
        let mut enc_block_64 = block_to_u64(&enc_block);

        unsafe {
            threefish_decrypt_block_64bit(
                &buf3f_64,
                enc_block_64.as_mut_ptr(),
                block_alt.as_mut_ptr(),
            );
        }

        assert_eq!(block, vec64_to_block(&enc_block_64));
    }

    #[test]
    fn encrypt_blocks_same_value() {
        let mut rng = FastRng::new();
        let mut buf3f_32 = [0; 1312];
        let mut buf3f_64 = ThreeFishBuffer64::default();
        let mut buf64 = [0; 64];

        for num_blocks in [1, 2, 3, 15, 21] {
            let mut data = Vec::with_capacity(64 * num_blocks);
            for _ in 0..(num_blocks * 64) {
                data.push(rng.gen());
            }

            let key = rng.gen::<[u8; 64]>();
            let tweek_seed = rng.gen::<[u8; 8]>();
            let mut body_32 = data.clone();
            let mut body_64 = data.clone();

            unsafe {
                ppenc_threefish512_encrypt(
                    key.as_ptr(),
                    tweek_seed.as_ptr(),
                    body_32.as_mut_ptr(),
                    num_blocks as u32,
                    buf3f_32.as_mut_ptr(),
                    buf64.as_mut_ptr(),
                );

                ppenc_threefish512_encrypt_64bit(
                    key.as_ptr(),
                    tweek_seed.as_ptr(),
                    body_64.as_mut_ptr(),
                    num_blocks as u32,
                    &mut buf3f_64,
                    buf64.as_mut_ptr(),
                );
            }

            assert_eq!(body_32, body_64);
            assert!(body_32 != data);
            assert!(body_64 != data);
        }
    }

    #[test]
    fn decrypt_blocks_same_value() {
        let mut rng = FastRng::new();
        let mut buf3f_32 = [0; 1312];
        let mut buf3f_64 = ThreeFishBuffer64::default();
        let mut buf64 = [0; 64];

        for num_blocks in [1, 2, 3, 15, 21] {
            let mut data = Vec::with_capacity(64 * num_blocks);
            for _ in 0..(num_blocks * 64) {
                data.push(rng.gen());
            }

            let key = rng.gen::<[u8; 64]>();
            let tweek_seed = rng.gen::<[u8; 8]>();
            let mut body_32 = data.clone();
            let mut body_64 = data.clone();

            unsafe {
                ppenc_threefish512_decrypt(
                    key.as_ptr(),
                    tweek_seed.as_ptr(),
                    body_32.as_mut_ptr(),
                    num_blocks as u32,
                    buf3f_32.as_mut_ptr(),
                    buf64.as_mut_ptr(),
                );

                ppenc_threefish512_decrypt_64bit(
                    key.as_ptr(),
                    tweek_seed.as_ptr(),
                    body_64.as_mut_ptr(),
                    num_blocks as u32,
                    &mut buf3f_64,
                    buf64.as_mut_ptr(),
                );
            }

            assert_eq!(body_32, body_64);
            assert!(body_32 != data);
            assert!(body_64 != data);
        }
    }
}
