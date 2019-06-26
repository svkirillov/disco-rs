extern crate disco_rs;

use disco_rs::asymmetric::*;
use disco_rs::symmentric::*;

#[test]
fn test_hash() {
	let input = b"hi, how are you?".to_vec();
	let hash = hash(&input, 32);
	let expected_hash = [
		0xed, 0xa8, 0x50, 0x6c, 0x1f, 0xb0, 0xbb, 0xcc, 0x3f, 0x62, 0x62, 0x6f, 0xef, 0x07, 0x4b,
		0xbf, 0x2d, 0x09, 0xa8, 0xc7, 0xc6, 0x08, 0xf3, 0xfa, 0x14, 0x82, 0xc9, 0xa6, 0x25, 0xd0,
		0x0f, 0x75,
	];

	assert_eq!(hash, &expected_hash[..]);
}

#[test]
fn test_sum() {
	let msg1 = b"hello".to_vec();
	let msg2 = b"how are you good sir?".to_vec();
	let msg3 = b"sure thing".to_vec();
	let fullmsg = [msg1.clone(), msg2.clone()].concat();

	let mut hash1 = DiscoHash::new(32);
	hash1.write(&msg1);
	hash1.write(&msg2);
	let out1 = hash1.sum();

	let mut hash2 = DiscoHash::new(32);
	hash2.write(&fullmsg);
	let out2 = hash2.sum();

	assert_eq!(out1, out2);

	let out3 = hash(&fullmsg, 32);

	assert_eq!(out1, out3);

	hash1.write(&msg3);
	let out1 = hash1.sum();

	hash2.write(&msg3);
	let out2 = hash2.sum();

	assert_eq!(out1, out2);

	let fullmsg = [fullmsg.clone(), msg3.clone()].concat();
	let out3 = hash(&fullmsg, 32);

	assert_eq!(out1, out3);
}

#[test]
fn test_tuplehash() {
	let msg1 = b"the plasma".to_vec();
	let msg2 = b"screen is broken, we need to do something about it!".to_vec();
	let msg3 = [
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x01, 0x02,
		0x03, 0x04, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	];
	let msg4 = b"HAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHA".to_vec();

	let mut hash1 = DiscoHash::new(32);
	hash1.write(&msg1);
	hash1.write(&msg2);
	hash1.write(&msg3.to_vec());
	let out1 = hash1.sum();

	let mut hash2 = DiscoHash::new(32);
	hash2.write_tuple(&msg1);
	hash2.write_tuple(&msg2);
	hash2.write_tuple(&msg3.to_vec());
	let out2 = hash2.sum();

	assert_ne!(out1, out2);

	let mut hash1 = DiscoHash::new(32);
	hash1.write_tuple(&msg1);
	hash1.write(&msg2);
	hash1.write(&msg3.to_vec());
	hash1.write_tuple(&msg4);
	let out1 = hash1.sum();

	let mut hash2 = DiscoHash::new(32);
	hash2.write_tuple(&msg1);
	hash2.write_tuple(&[msg2, msg3.to_vec()].concat());
	hash2.write_tuple(&msg4);
	let out2 = hash2.sum();

	assert_eq!(out1, out2);
}

#[test]
fn test_derive_keys() {
	let input = b"hi, how are you?".to_vec();
	let key = derive_keys(&input, 64);
	let expected_key = [
		0xd6, 0x35, 0x0b, 0xb9, 0xb8, 0x38, 0x84, 0x77, 0x4f, 0xb9, 0xb0, 0x88, 0x16, 0x80, 0xfc,
		0x65, 0x6b, 0xe1, 0x07, 0x1f, 0xff, 0x75, 0xd3, 0xfa, 0x94, 0x51, 0x9d, 0x50, 0xa1, 0x0b,
		0x92, 0x64, 0x4e, 0x3c, 0xc1, 0xca, 0xe1, 0x66, 0xa6, 0x01, 0x67, 0xd7, 0xbf, 0x00, 0x13,
		0x70, 0x18, 0x34, 0x5b, 0xb8, 0x05, 0x7b, 0xe4, 0xb0, 0x9f, 0x93, 0x7b, 0x0e, 0x12, 0x06,
		0x6d, 0x5d, 0xc3, 0xdf,
	];

	assert_eq!(key, &expected_key[..]);
}

#[test]
fn test_nonce_size() {
	let key = vec![
		0xed, 0xa8, 0x50, 0x6c, 0x1f, 0xb0, 0xbb, 0xcc, 0x3f, 0x62, 0x62, 0x6f, 0xef, 0x07, 0x4b,
		0xbf, 0x2d, 0x09, 0xa8, 0xc7, 0xc6, 0x08, 0xf3, 0xfa, 0x14, 0x82, 0xc9, 0xa6, 0x25, 0xd0,
		0x0f, 0x75,
	];
	let plaintext = b"hello, how are you?".to_vec();
	let ciphertext = encrypt(&key, &plaintext);

	assert_eq!(ciphertext.len(), 19 + 16 + 24);
}

#[test]
fn test_integrity_correctness() {
	let key = vec![
		0xed, 0xa8, 0x50, 0x6c, 0x1f, 0xb0, 0xbb, 0xcc, 0x3f, 0x62, 0x62, 0x6f, 0xef, 0x07, 0x4b,
		0xbf, 0x2d, 0x09, 0xa8, 0xc7, 0xc6, 0x08, 0xf3, 0xfa, 0x14, 0x82, 0xc9, 0xa6, 0x25, 0xd0,
		0x0f, 0x75,
	];
	let msg = b"hoy, how are you?".to_vec();
	let boxed_pt = protect_integrity(&key, &msg);
	let unboxed_pt = verify_integrity(&key, &boxed_pt).expect("verify_integrity failed");

	assert_eq!(unboxed_pt, msg);
}

#[test]
fn test_encrypt_decrypt() {
	let key = vec![
		0xed, 0xa8, 0x50, 0x6c, 0x1f, 0xb0, 0xbb, 0xcc, 0x3f, 0x62, 0x62, 0x6f, 0xef, 0x07, 0x4b,
		0xbf, 0x2d, 0x09, 0xa8, 0xc7, 0xc6, 0x08, 0xf3, 0xfa, 0x14, 0x82, 0xc9, 0xa6, 0x25, 0xd0,
		0x0f, 0x75,
	];
	let plaintexts = [
		&b""[..],
		&b"a"[..],
		&b"ab"[..],
		&b"abc"[..],
		&b"abcd"[..],
		&b"short"[..],
		&b"hello, how are you?"[..],
		&b"this is very short"[..],
		&b"this is very long though, like, very very long, should we test very very long\
           things here?"[..],
	];

	for plaintext in plaintexts.into_iter().map(|s| s.to_vec()) {
		let auth_ciphertext = encrypt(&key, &plaintext);
		let decrypted = decrypt(&key, &auth_ciphertext).expect("decrypt auth failed");

		assert_eq!(decrypted, plaintext);
	}
}

#[test]
fn test_encrypt_decrypt_and_authenticate() {
	let key = vec![
		0xed, 0xa8, 0x50, 0x6c, 0x1f, 0xb0, 0xbb, 0xcc, 0x3f, 0x62, 0x62, 0x6f, 0xef, 0x07, 0x4b,
		0xbf, 0x2d, 0x09, 0xa8, 0xc7, 0xc6, 0x08, 0xf3, 0xfa, 0x14, 0x82, 0xc9, 0xa6, 0x25, 0xd0,
		0x0f, 0x75,
	];
	let plaintexts = [
		&b""[..],
		&b"a"[..],
		&b"ab"[..],
		&b"abc"[..],
		&b"abcd"[..],
		&b"short"[..],
		&b"hello, how are you?"[..],
		&b"this is very short"[..],
		&b"this is very long though, like, very very long, should we test very very long\
           things here?"[..],
	];
	let ads = [
		&b""[..],
		&b"a"[..],
		&b"ab"[..],
		&b"abc"[..],
		&b"abcd"[..],
		&b"short"[..],
		&b"hello, how are you?"[..],
		&b"this is very short"[..],
		&b"this is very long though, like, very very long, should we test very very long\
           things here?"[..],
	];

	for plaintext in plaintexts.into_iter().map(|s| s.to_vec()) {
		for ad in ads.into_iter().map(|s| s.to_vec()) {
			let auth_ciphertext = encrypt_and_authenticate(&key, &plaintext, &ad);
			let decrypted =
				decrypt_and_authenticate(&key, &auth_ciphertext, &ad).expect("decrypt auth failed");

			assert_eq!(decrypted, plaintext);
		}
	}
}
