use std::fmt;
use std::result;

mod blockcipher;
mod cprng;
mod hash;

#[repr(C)]
struct PPEncHeader {
    seq_num: u32,
    body_len: u32,
    body_key_num: u16,
    inner_salt: *const u8,
    tweek_seed: *const u8,
    body_checksum: *const u8,
}

extern "C" {
    fn ppenc_sizeof_receiver() -> u32;
    fn ppenc_receiver_init(
        receiver: *mut u8,
        header_key_salt: *const u8,
        header_state_init: *const u8,
        header_rng_nonce: *const u8,
        body_key_salt: *const u8,
        body_key_state0: *const u8,
        buf1400: *mut u8,
    );
    fn ppenc_receiver_read_header(
        receiver: *mut u8,
        header: *mut PPEncHeader,
        raw_header: *mut u8,
    ) -> u16;

    fn ppenc_receiver_read_body(
        receiver: *mut u8,
        header: *const PPEncHeader,
        body: *mut u8,
        response_mac: *mut u8,
        buf1400: *mut u8,
    ) -> u16;

    fn ppenc_body_padded_len(body_len: u32) -> u32;
}

#[derive(Copy, Clone, Debug)]
pub enum Error {
    BadVersion,
    BadSeqNum,
    BadBodyChecksum,
    BodyKeyInPast,
    Unknown(u16),
}

impl fmt::Display for Error {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            w,
            "{}",
            match self {
                Error::BadVersion => "version not supported".to_string(),
                Error::BadSeqNum => "sequence number not expected - out of order".to_string(),
                Error::BadBodyChecksum => "body checksum invalid".to_string(),
                Error::BodyKeyInPast => "body key is in the past and may not be used".to_string(),
                Error::Unknown(i) => i.to_string(),
            }
        )
    }
}

pub type Result<T> = result::Result<T, Error>;

pub struct Receiver {
    receiver: Vec<u8>,
    buf1400: Vec<u8>,
}

pub struct Header<'h> {
    seq_num: u32,
    body_len: u32,
    body_key_num: u16,
    inner_salt: &'h [u8],
    body_checksum: &'h [u8],
    tweek_seed: &'h [u8],
}

impl Receiver {
    pub fn new(
        header_key_salt: &[u8; 16],
        header_state_init: &[u8; 32],
        header_rng_nonce: &[u8; 12],
        body_key_salt: &[u8; 16],
        body_key_state0: &[u8; 32],
    ) -> Self {
        let mut receiver = Vec::new();
        let mut buf1400 = vec![0; 1400];
        unsafe {
            receiver.resize(ppenc_sizeof_receiver() as usize, 0);
            ppenc_receiver_init(
                receiver.as_mut_ptr(),
                header_key_salt.as_ptr(),
                header_state_init.as_ptr(),
                header_rng_nonce.as_ptr(),
                body_key_salt.as_ptr(),
                body_key_state0.as_ptr(),
                buf1400.as_mut_ptr(),
            );
        }

        Self { receiver, buf1400 }
    }

    pub fn read_header<'r, 'h: 'r>(&mut self, raw_header: &'r mut [u8; 32]) -> Result<Header<'h>> {
        let mut ppenc_header = PPEncHeader {
            seq_num: 0,
            body_len: 0,
            body_key_num: 0,
            inner_salt: std::ptr::null(),
            tweek_seed: std::ptr::null(),
            body_checksum: std::ptr::null(),
        };
        check_err(unsafe {
            ppenc_receiver_read_header(
                self.receiver.as_mut_ptr(),
                &mut ppenc_header,
                raw_header.as_mut_ptr(),
            )
        })?;

        let inner_salt = unsafe { std::slice::from_raw_parts(ppenc_header.inner_salt, 6) };
        let tweek_seed = unsafe { std::slice::from_raw_parts(ppenc_header.tweek_seed, 8) };
        let body_checksum = unsafe { std::slice::from_raw_parts(ppenc_header.body_checksum, 8) };

        Ok(Header {
            seq_num: ppenc_header.seq_num,
            body_len: ppenc_header.body_len,
            body_key_num: ppenc_header.body_key_num,
            inner_salt,
            tweek_seed,
            body_checksum,
        })
    }

    pub fn read_body(&mut self, header: Header<'_>, body: &mut Vec<u8>) -> Result<[u8; 32]> {
        // Make sure we have enough space to compute response_mac hash
        let mut response_mac = [0u8; 32];
        check_err(unsafe {
            ppenc_receiver_read_body(
                self.receiver.as_mut_ptr(),
                &header.as_ppenc_header(),
                body.as_mut_ptr(),
                response_mac.as_mut_ptr(),
                self.buf1400.as_mut_ptr(),
            )
        })?;
        body.truncate(header.body_len as usize);
        Ok(response_mac)
    }
}

impl<'h> Header<'h> {
    unsafe fn as_ppenc_header(&self) -> PPEncHeader {
        PPEncHeader {
            seq_num: self.seq_num,
            body_len: self.body_len,
            body_key_num: self.body_key_num,
            inner_salt: self.inner_salt.as_ptr(),
            tweek_seed: self.tweek_seed.as_ptr(),
            body_checksum: self.body_checksum.as_ptr(),
        }
    }

    pub fn body_padded_len(&self) -> usize {
        unsafe { ppenc_body_padded_len(self.body_len) as usize }
    }
}

fn check_err(err: u16) -> Result<()> {
    match err {
        0 => Ok(()),
        1 => Err(Error::BadVersion),
        2 => Err(Error::BadSeqNum),
        3 => Err(Error::BadBodyChecksum),
        4 => Err(Error::BodyKeyInPast),
        _ => Err(Error::Unknown(err)),
    }
}

#[cfg(test)]
mod tests {
    use random_fast_rng::{FastRng, Random};

    use super::*;

    extern "C" {
        fn header_scramble(header: *mut u8);
        fn header_scramble_inverse(header: *mut u8);

        /* sender rng */
        fn ppenc_sizeof_sender_rng() -> u32;
        fn ppenc_sender_rng_init(sender_rng: *mut u8, key: *const u8, nonce: *const u8);
        fn ppenc_sender_rng_nbytes(sender_rng: *mut u8, dst: *mut u8, num_bytes: u16);

        /* sender */
        fn ppenc_sizeof_sender() -> u32;
        fn ppenc_sender_init(
            sender: *mut u8,
            sender_rng: *mut u8,
            header_salt: *const u8,
            header_state_init: *const u8,
            header_rng_nonce: *const u8,
            body_salt: *const u8,
            body_state0: *const u8,
            buf1400: *mut u8,
        );
        fn ppenc_sender_new_msg(
            sender: *mut u8,
            header_buf: *mut u8,
            body: *mut u8,
            body_len: u32,
            response_mac: *mut u8,
            buf1400: *mut u8,
        ) -> u32;

        fn ppenc_sender_new_body_key(sender: *mut u8, buf1400: *mut u8);
    }

    #[test]
    fn send_receive() {
        let mut rng = FastRng::new();
        let header_key_salt = rng.gen::<[u8; 16]>();
        let header_state_init = rng.gen::<[u8; 32]>();
        let header_rng_nonce = rng.gen::<[u8; 12]>();
        let body_salt = rng.gen::<[u8; 16]>();
        let body_state0 = rng.gen::<[u8; 32]>();
        let mut sender_rng = Vec::with_capacity(64);
        sender_rng.resize(unsafe { ppenc_sizeof_sender_rng() as usize }, 0);
        let mut sender = Vec::with_capacity(24);
        sender.resize(unsafe { ppenc_sizeof_sender() as usize }, 0);
        let mut buf1400 = vec![0; 1400];

        unsafe {
            ppenc_sender_rng_init(
                sender_rng.as_mut_ptr(),
                (rng.gen::<[u8; 32]>()).as_ptr(),
                (rng.gen::<[u8; 8]>()).as_ptr(),
            );

            ppenc_sender_init(
                sender.as_mut_ptr(),
                sender_rng.as_mut_ptr(),
                header_key_salt.as_ptr(),
                header_state_init.as_ptr(),
                header_rng_nonce.as_ptr(),
                body_salt.as_ptr(),
                body_state0.as_ptr(),
                buf1400.as_mut_ptr(),
            );
        }

        let mut receiver = Receiver::new(
            &header_key_salt,
            &header_state_init,
            &header_rng_nonce,
            &body_salt,
            &body_state0,
        );

        for (seq_num, msg_len) in [1, 2, 3, 62, 63, 64, 65, 66, 126, 127, 128, 129, 130]
            .into_iter()
            .enumerate()
        {
            let mut header_raw = [0u8; 32];
            let mut response_mac = [0u8; 32];
            let mut body = Vec::with_capacity(msg_len);
            body.resize(msg_len, 0);
            for b in body.iter_mut() {
                *b = rng.gen();
            }
            let body2 = body.clone();

            /* space at the end for padding/hash padding */
            body.resize(body.len() + 71, 0);

            /* "send" a new message */
            let body_padded_len = unsafe {
                ppenc_sender_new_msg(
                    sender.as_mut_ptr(),
                    header_raw.as_mut_ptr(),
                    body.as_mut_ptr(),
                    msg_len as u32,
                    response_mac.as_mut_ptr(),
                    buf1400.as_mut_ptr(),
                )
            };

            let header = receiver
                .read_header(&mut header_raw)
                .expect("couldn't parse header");
            assert_eq!(header.body_len, msg_len as u32);
            assert_eq!(header.body_padded_len(), body_padded_len as usize);
            assert_eq!(header.seq_num, (seq_num + 1) as u32);

            let response_mac2 = receiver
                .read_body(header, &mut body)
                .expect("couldn't read body");

            assert_eq!(response_mac, response_mac2);
            assert_eq!(body, body2);

            if rng.gen::<u8>() & 1 != 0 {
                unsafe {
                    ppenc_sender_new_body_key(sender.as_mut_ptr(), buf1400.as_mut_ptr());
                }
            }
        }
    }

    #[test]
    fn header_scramble_() {
        let mut header = FastRng::new().gen::<[u8; 32]>();
        let header2 = header.clone();

        unsafe {
            header_scramble(header.as_mut_ptr());
            assert!(header != header2);
            header_scramble_inverse(header.as_mut_ptr());
        }

        assert_eq!(header, header2);
    }

    #[test]
    fn sender_rng() {
        use chacha::KeyStream;

        let mut rng = FastRng::new();
        let key = rng.gen::<[u8; 32]>();
        let nonce = rng.gen::<[u8; 8]>();
        let mut c8 = chacha::ChaCha::new_chacha8(&key, &nonce);
        let mut sender_rng = Vec::with_capacity(16);
        sender_rng.resize(unsafe { ppenc_sizeof_sender_rng() as usize }, 0);

        unsafe {
            ppenc_sender_rng_init(sender_rng.as_mut_ptr(), key.as_ptr(), nonce.as_ptr());
        }

        for num_bytes in [1, 5, 31, 32, 33, 63, 64, 65] {
            let mut bytes = Vec::with_capacity(num_bytes);
            bytes.resize(num_bytes, 0);
            unsafe {
                ppenc_sender_rng_nbytes(
                    sender_rng.as_mut_ptr(),
                    bytes.as_mut_ptr(),
                    num_bytes as u16,
                );
            }

            c8.xor_read(&mut bytes)
                .expect("couldn't read chacha8 bytes");

            for b in bytes {
                assert_eq!(b, 0);
            }
        }
    }
}
