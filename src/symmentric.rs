use rand::{thread_rng, RngCore};
use strobe_rs::{AuthError, SecParam, Strobe};

pub const NONCE_SIZE: usize = 192 / 8;
pub const TAG_SIZE: usize = 16;
pub const MINIMUM_CIPHERTEXT_SIZE: usize = NONCE_SIZE + TAG_SIZE;

pub struct DiscoHash {
	strobe_state: Strobe,
	streaming: bool,
	output_len: usize,
}

impl DiscoHash {
	pub fn new(output_len: usize) -> DiscoHash {
		if output_len < 32 {
			panic!(
				"disco: an output length smaller than 256-bit (32 bytes) \
				 has security consequences"
			);
		}

		DiscoHash {
			strobe_state: Strobe::new("DiscoHash".as_bytes().to_vec(), SecParam::B128),
			streaming: false,
			output_len,
		}
	}

	pub fn write(&mut self, input_data: &Vec<u8>) {
		self.strobe_state
			.ad(input_data.clone(), None, self.streaming);
		self.streaming = true;
	}

	pub fn write_tuple(&mut self, input_data: &Vec<u8>) {
		self.strobe_state.ad(input_data.clone(), None, false);
	}

	pub fn sum(&self) -> Vec<u8> {
		let mut reader = self.strobe_state.clone();
		reader.prf(self.output_len, None, false)
	}

	pub fn clone(&self) -> DiscoHash {
		DiscoHash {
			strobe_state: self.strobe_state.clone(),
			streaming: self.streaming,
			output_len: self.output_len,
		}
	}
}

pub fn hash(input_data: &Vec<u8>, output_len: usize) -> Vec<u8> {
	let mut h = DiscoHash::new(output_len);
	h.write(input_data);
	h.sum()
}

pub fn derive_keys(input_key: &Vec<u8>, output_len: usize) -> Vec<u8> {
	if input_key.len() < 16 {
		panic!(
			"disco: deriving keys from a value smaller than 128-bit (16 bytes) has \
			 security consequences"
		)
	}

	let mut s = Strobe::new("DiscoKDF".as_bytes().to_vec(), SecParam::B128);
	s.ad(input_key.clone(), None, false);
	s.prf(output_len, None, false)
}

pub fn protect_integrity(key: &Vec<u8>, plaintext: &Vec<u8>) -> Vec<u8> {
	if key.len() < 16 {
		panic!("disco: using a key smaller than 128-bit (16 bytes) has security consequences");
	}

	let mut s = Strobe::new("DiscoMAC".as_bytes().to_vec(), SecParam::B128);
	s.ad(key.clone(), None, false);
	s.ad(plaintext.clone(), None, false);
	let mac = s.send_mac(TAG_SIZE, None, false);

	let mut auth_plain_text = plaintext.clone();
	auth_plain_text.extend(&mac);
	auth_plain_text
}

pub fn verify_integrity(key: &Vec<u8>, plaintext_and_mac: &Vec<u8>) -> Result<Vec<u8>, AuthError> {
	if key.len() < 16 {
		panic!("disco: using a key smaller than 128-bit (16 bytes) has security consequences");
	}

	if plaintext_and_mac.len() < TAG_SIZE {
		panic!("disco: plaintext does not contain an integrity tag");
	}

	let offset = plaintext_and_mac.len() - TAG_SIZE;
	let (plaintext, mac) = plaintext_and_mac.split_at(offset);

	let plaintext = plaintext.to_vec();
	let mac = mac.to_vec();

	let mut s = Strobe::new("DiscoMAC".as_bytes().to_vec(), SecParam::B128);
	s.ad(key.clone(), None, false);
	s.ad(plaintext.clone(), None, false);

	match s.recv_mac(mac, None, false) {
		Ok(_) => Ok(plaintext.clone()),
		Err(ae) => Err(ae),
	}
}

pub fn encrypt(key: &Vec<u8>, plaintext: &Vec<u8>) -> Vec<u8> {
	if key.len() < 16 {
		panic!("disco: using a key smaller than 128-bit (16 bytes) has security consequences");
	}

	let mut s = Strobe::new("DiscoAE".as_bytes().to_vec(), SecParam::B128);

	// Absorb the key
	s.ad(key.clone(), None, false);

	// Generate 192-bit nonce and absorb it
	let mut rng = thread_rng();
	let mut nonce = vec![0u8; NONCE_SIZE];
	rng.fill_bytes(nonce.as_mut_slice());
	s.ad(nonce.clone(), None, false);

	// nonce + send_ENC(plaintext) + send_MAC(16)
	let mut ciphertext = nonce.as_slice().to_vec();
	ciphertext.extend(s.send_enc(plaintext.clone(), None, false));
	ciphertext.extend(s.send_mac(TAG_SIZE, None, false));

	ciphertext
}

pub fn decrypt(key: &Vec<u8>, ciphertext: &Vec<u8>) -> Result<Vec<u8>, AuthError> {
	if key.len() < 16 {
		panic!("disco: using a key smaller than 128-bit (16 bytes) has security consequences");
	}

	if ciphertext.len() < MINIMUM_CIPHERTEXT_SIZE {
		panic!(
			"disco: ciphertext is too small, it should contain at a minimum a 192-bit nonce \
			 and a 128-bit tag"
		)
	}

	let mut s = Strobe::new("DiscoAE".as_bytes().to_vec(), SecParam::B128);

	// Absorb the key and nonce
	s.ad(key.clone(), None, false);
	s.ad(ciphertext[..NONCE_SIZE].to_vec(), None, false);

	// decrypt
	let plaintext = s.recv_enc(
		ciphertext[NONCE_SIZE..ciphertext.len() - TAG_SIZE].to_vec(),
		None,
		false,
	);

	match s.recv_mac(
		ciphertext[ciphertext.len() - TAG_SIZE..].to_vec(),
		None,
		false,
	) {
		Ok(_) => Ok(plaintext),
		Err(auth_error) => Err(auth_error),
	}
}

pub fn encrypt_and_authenticate(key: &Vec<u8>, plaintext: &Vec<u8>, ad: &Vec<u8>) -> Vec<u8> {
	if key.len() < 16 {
		panic!("disco: using a key smaller than 128-bit (16 bytes) has security consequences");
	}

	let mut s = Strobe::new("DiscoAEAD".as_bytes().to_vec(), SecParam::B128);

	// Absorb the key
	s.ad(key.clone(), None, false);
	// absorb the AD
	s.ad(ad.clone(), None, false);

	// Generate 192-bit nonce and absorb it
	let mut rng = thread_rng();
	let mut nonce = vec![0u8; NONCE_SIZE];
	rng.fill_bytes(nonce.as_mut_slice());
	s.ad(nonce.clone(), None, false);

	// nonce + send_ENC(plaintext) + send_MAC(16)
	let mut ciphertext = nonce.as_slice().to_vec();
	ciphertext.extend(s.send_enc(plaintext.clone(), None, false));
	ciphertext.extend(s.send_mac(TAG_SIZE, None, false));

	ciphertext
}

pub fn decrypt_and_authenticate(
	key: &Vec<u8>,
	ciphertext: &Vec<u8>,
	ad: &Vec<u8>,
) -> Result<Vec<u8>, AuthError> {
	if key.len() < 16 {
		panic!("disco: using a key smaller than 128-bit (16 bytes) has security consequences");
	}

	if ciphertext.len() < MINIMUM_CIPHERTEXT_SIZE {
		panic!(
			"disco: ciphertext is too small, it should contain at a minimum a 192-bit nonce \
			 and a 128-bit tag"
		)
	}

	let mut s = Strobe::new("DiscoAEAD".as_bytes().to_vec(), SecParam::B128);

	// Absorb the key and nonce
	s.ad(key.clone(), None, false);
	// absorb the AD
	s.ad(ad.clone(), None, false);
	// absorb the nonce
	s.ad(ciphertext[..NONCE_SIZE].to_vec(), None, false);

	// decrypt
	let plaintext = s.recv_enc(
		ciphertext[NONCE_SIZE..ciphertext.len() - TAG_SIZE].to_vec(),
		None,
		false,
	);

	match s.recv_mac(
		ciphertext[ciphertext.len() - TAG_SIZE..].to_vec(),
		None,
		false,
	) {
		Ok(_) => Ok(plaintext),
		Err(auth_error) => Err(auth_error),
	}
}
