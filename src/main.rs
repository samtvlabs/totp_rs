extern crate hex;
extern crate hmac;
extern crate sha2;

use hex::{decode, encode};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha512 = Hmac<Sha512>;

fn hmac_sha(key: &[u8], text: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha512::new_from_slice(key).unwrap();
    mac.update(text);
    mac.finalize().into_bytes().to_vec()
}

fn hex_str_to_bytes(s: &str) -> Vec<u8> {
    decode(s).unwrap()
}

fn generate_totp(key: &str, time_str: &str, return_digits: usize) -> String {
    let mut time_str = time_str.to_string();
    while time_str.len() < 16 {
        time_str.insert(0, '0');
    }

    let msg = hex_str_to_bytes(&time_str);
    let k = hex_str_to_bytes(key);

    let h = hmac_sha(&k, &msg);

    let offset = (h[h.len() - 1] & 0xf) as usize;

    let b = ((u64::from(h[offset]) & 0x7f) << 24)
        | ((u64::from(h[offset + 1]) & 0xff) << 16)
        | ((u64::from(h[offset + 2]) & 0xff) << 8)
        | (u64::from(h[offset + 3]) & 0xff);

    let otp = b % 10u64.pow(return_digits as u32);

    let mut result = otp.to_string();

    while result.len() < return_digits {
        result.insert(0, '0');
    }

    result
}

fn secret(key: &str) -> String {
    encode(key.as_bytes())
}

fn main() {
    let t0 = 0;
    let x = 30;
    let mut steps = "0".to_string();

    let te = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let t = (te - t0) / x;

    println!("{}", t);
    steps = format!("{:X}", t);

    while steps.len() < 16 {
        steps.insert(0, '0');
    }

    let seed = secret("some_top_secret");
    let s = generate_totp(&seed, &steps, 10);

    println!("{}", s);
}
