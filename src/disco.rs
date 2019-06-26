use crate::asymmetric;
use crate::asymmetric::*;
use crate::patterns::{HandshakePattern, MessagePattern, Token};
use std::collections::VecDeque;
use strobe_rs::{AuthError, SecParam, Strobe};
use x25519_dalek::PublicKey;

const TAG_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;
pub(crate) const NOISE_MAX_MSG_SIZE: usize = 65535;
pub(crate) const NOISE_TAG_SIZE: usize = 16;
pub(crate) const NOISE_MAX_PLAINTEXT_SIZE: usize = NOISE_MAX_MSG_SIZE - NOISE_TAG_SIZE;

pub enum DiscoWriteError {
	TooLongErr,
}

pub enum DiscoReadError {
	ParseErr(&'static str),
	AuthErr,
	TooLongErr,
}

//
// SymmetricState object
//

struct SymmetricState {
	strobe_state: Strobe,
	is_keyed: bool,
}

impl SymmetricState {
	pub fn new(proto: Vec<u8>) -> SymmetricState {
		SymmetricState {
			strobe_state: Strobe::new(proto, SecParam::B128),
			is_keyed: false,
		}
	}

	pub fn mix_key(&mut self, input_key_material: &Vec<u8>) {
		self.strobe_state
			.ad(input_key_material.clone(), None, false);
		self.is_keyed = true;
	}

	pub fn mix_hash(&mut self, data: &Vec<u8>) {
		self.strobe_state.ad(data.clone(), None, false);
	}

	pub fn mix_key_and_hash(&mut self, input_key_material: &Vec<u8>) {
		self.strobe_state
			.ad(input_key_material.clone(), None, false);
	}

	pub fn get_handshake_hash(&mut self) -> Vec<u8> {
		self.strobe_state.prf(KEY_SIZE, None, false)
	}

	fn encrypt_and_hash(&mut self, plaintext: &Vec<u8>) -> Vec<u8> {
		if self.is_keyed {
			let ciphertext = self.strobe_state.send_enc(plaintext.clone(), None, false);

			let mac = self.strobe_state.send_mac(TAG_SIZE, None, false);

			[ciphertext, mac].concat()
		} else {
			plaintext.to_owned()
		}
	}

	fn decrypt_and_hash(&mut self, ciphertext: &Vec<u8>) -> Result<Vec<u8>, AuthError> {
		if self.is_keyed {
			if ciphertext.len() < TAG_SIZE {
				panic!("disco: the received payload is shorter 16 bytes");
			}

			let mut ciphertext = ciphertext.clone();
			let mac = ciphertext.split_off(ciphertext.len() - TAG_SIZE);

			let plaintext = self.strobe_state.recv_enc(ciphertext.clone(), None, false);

			match self.strobe_state.recv_mac(mac, None, false) {
				Ok(_) => Ok(plaintext),
				Err(auth_error) => Err(auth_error),
			}
		} else {
			Ok(ciphertext.clone())
		}
	}

	fn split(self) -> (Strobe, Strobe) {
		let mut s1 = self.strobe_state.clone();
		s1.ad(b"initiator".to_vec(), None, false);
		s1.ratchet(KEY_SIZE, None, false);

		let mut s2 = self.strobe_state;
		s2.ad(b"responder".to_vec(), None, false);
		s2.ratchet(KEY_SIZE, None, false);

		(s1, s2)
	}
}

//
// HandshakeState object
//

pub(crate) struct HandshakeState {
	symmetric_state: SymmetricState, // the SymmetricState object
	s: Option<KeyPair>,              // the local static key pair
	e: Option<KeyPair>,              // the local ephemeral key pair
	rs: Option<PublicKey>,           // the remote party's static public key
	re: Option<PublicKey>,           // the remote party's ephemeral public key
	initiator: bool,                 // Are we the initiator?
	message_patterns: VecDeque<MessagePattern>, // A sequence of message pattern.
	should_write: bool,              // Is my role to `write_msg` (as opposed to `read_msg`)?
	psk: Option<Vec<u8>>,            // Pre-shared key.
}

impl HandshakeState {
	pub fn new(
		handshake_type: &HandshakePattern,
		initiator: bool,
		prologue: &Vec<u8>,
		s: Option<KeyPair>,
		e: Option<KeyPair>,
		rs: Option<PublicKey>,
		re: Option<PublicKey>,
		psk: Option<Vec<u8>>,
	) -> HandshakeState {
		let proto: Vec<u8> = [b"Noise_", handshake_type.name, b"_25519_STROBEv1.0.2"].concat();

		let mut symmetric_state = SymmetricState::new(proto);

		symmetric_state.mix_hash(prologue);

		let message_patterns = VecDeque::from(handshake_type.message_patterns.to_vec());
		let should_write = initiator;

		let mut h = HandshakeState {
			symmetric_state,
			s,
			e,
			rs,
			re,
			initiator,
			message_patterns,
			should_write,
			psk,
		};

		// Initiator pre-message pattern
		for token in handshake_type.pre_message_patterns[0] {
			if let Token::S = token {
				if initiator {
					let s = match &h.s {
						Some(s) => s,
						None => panic!("disco: the static key of the client should be set"),
					};
					h.symmetric_state
						.mix_hash(&s.get_public_key().as_bytes().to_vec());
				} else {
					let rs = match &h.rs {
						Some(rs) => rs,
						None => panic!("disco: the remote static key of the server should be set"),
					};
					h.symmetric_state.mix_hash(&rs.as_bytes().to_vec());
				}
			} else {
				panic!("disco: token of pre-message not supported");
			}
		}

		// Responder pre-message pattern
		for token in handshake_type.pre_message_patterns[1] {
			if let Token::S = token {
				if initiator {
					let rs = match &h.rs {
						Some(rs) => rs,
						None => panic!("disco: the remote static key of the server should be set"),
					};
					h.symmetric_state.mix_hash(&rs.as_bytes().to_vec());
				} else {
					let s = match &h.s {
						Some(s) => s,
						None => panic!("disco: the static key of the client should be set"),
					};
					h.symmetric_state
						.mix_hash(&s.get_public_key().as_bytes().to_vec());
				}
			} else {
				panic!("disco: token of pre-message not supported");
			}
		}

		h
	}

	pub(crate) fn write_message(
		&mut self,
		payload: &Vec<u8>,
	) -> Result<(Vec<u8>, bool), DiscoWriteError> {
		if !self.should_write {
			panic!("disco: unexpected call to write_message should be read_message");
		}

		// do we have a token to process?
		if self.message_patterns.is_empty() || self.message_patterns[0].is_empty() {
			panic!("disco: no more tokens or message patterns to write");
		}

		if payload.len() > NOISE_MAX_PLAINTEXT_SIZE {
			return Err(DiscoWriteError::TooLongErr);
		}

		// This will be our output
		let mut message_buffer = Vec::new();

		// We can unwrap because we just checked message_pats.len() != 0
		let pat = self.message_patterns.pop_front().unwrap();
		for token in pat {
			match token {
				Token::E => {
					let e = KeyPair::gen();

					let e_public_key = e.get_public_key();
					let e_bytes = e_public_key.as_bytes();

					message_buffer.extend_from_slice(e_bytes);

					self.symmetric_state.mix_hash(&e_bytes.to_vec());
					if self.psk.is_some() {
						self.symmetric_state.mix_key(&e_bytes.to_vec());
					}

					self.e = Some(e);
				}

				Token::S => {
					let s = self.s.clone().unwrap().get_public_key().as_bytes().to_vec();
					let ciphertext = self.symmetric_state.encrypt_and_hash(&s);

					message_buffer.extend(ciphertext);
				}

				Token::EE => {
					let ee_key =
						asymmetric::dh(&self.e.clone().unwrap(), &self.re.clone().unwrap());

					self.symmetric_state.mix_key(&ee_key.as_bytes().to_vec());
				}

				Token::ES => {
					if self.initiator {
						let es_key =
							asymmetric::dh(&self.e.clone().unwrap(), &self.rs.clone().unwrap());

						self.symmetric_state.mix_key(&es_key.as_bytes().to_vec());
					} else {
						let es_key =
							asymmetric::dh(&self.s.clone().unwrap(), &self.re.clone().unwrap());

						self.symmetric_state.mix_key(&es_key.as_bytes().to_vec());
					}
				}

				Token::SE => {
					if self.initiator {
						let se_key =
							asymmetric::dh(&self.s.clone().unwrap(), &self.re.clone().unwrap());

						self.symmetric_state.mix_key(&se_key.as_bytes().to_vec());
					} else {
						let se_key =
							asymmetric::dh(&self.e.clone().unwrap(), &self.rs.clone().unwrap());

						self.symmetric_state.mix_key(&se_key.as_bytes().to_vec());
					}
				}

				Token::SS => {
					let ss_key =
						asymmetric::dh(&self.s.clone().unwrap(), &self.rs.clone().unwrap());

					self.symmetric_state.mix_key(&ss_key.as_bytes().to_vec());
				}

				Token::Psk => {
					let psk = self
						.psk
						.clone()
						.expect("disco: In processing psk token, no preshared key is set");
					self.symmetric_state.mix_key_and_hash(&psk);
				}
			}
		}

		let ciphertext = self.symmetric_state.encrypt_and_hash(payload);
		message_buffer.extend(ciphertext);

		// Next time it's our turn to read
		self.should_write = false;

		// If there's nothing left to read, say we're ready to split()
		if self.message_patterns.len() == 0 {
			Ok((message_buffer, true))
		} else {
			Ok((message_buffer, false))
		}
	}

	pub(crate) fn read_message(
		&mut self,
		message: &Vec<u8>,
	) -> Result<(Vec<u8>, bool), DiscoReadError> {
		if self.should_write {
			panic!("disco: unexpected call to read_message should be write_message")
		}

		// do we have a token to process?
		if self.message_patterns.is_empty() || self.message_patterns[0].is_empty() {
			panic!("disco: no more tokens or message patterns to write");
		}

		if message.len() > NOISE_MAX_PLAINTEXT_SIZE {
			return Err(DiscoReadError::TooLongErr);
		}

		let mut msg = message.clone();

		let pat = self.message_patterns.pop_front().unwrap();
		for token in pat {
			match token {
				Token::E => {
					if msg.len() < DH_SIZE {
						return Err(DiscoReadError::ParseErr(
							"disco: In processing e token, msg too short",
						));
					}
					let tmp = msg.split_off(DH_SIZE);
					let mut e = [0u8; KEY_SIZE];
					e.copy_from_slice(&msg);
					self.re = Some(PublicKey::from(e));
					self.symmetric_state
						.mix_hash(&self.re.clone().unwrap().as_bytes().to_vec());
					if self.psk.is_some() {
						self.symmetric_state
							.mix_key(&self.re.clone().unwrap().as_bytes().to_vec());
					}
					msg = tmp;
				}

				Token::S => {
					let tag_size = if self.symmetric_state.is_keyed {
						TAG_SIZE
					} else {
						0
					};
					let len = msg.len();
					if len < DH_SIZE + tag_size {
						return Err(DiscoReadError::ParseErr(
							"disco: In processing s token, msg too short",
						));
					}
					// tmp holds the rest of the message, msg holds the pubkey
					let tmp = msg.split_off(DH_SIZE + tag_size);
					let ciphertext = msg;
					msg = tmp;
					let plaintext = self
						.symmetric_state
						.decrypt_and_hash(&ciphertext)
						.map_err(|_| DiscoReadError::AuthErr)?;
					let mut s = [0u8; DH_SIZE];
					s.copy_from_slice(&plaintext);
					self.rs = Some(PublicKey::from(s));
				}

				Token::EE => {
					let ee_key =
						asymmetric::dh(&self.e.clone().unwrap(), &self.re.clone().unwrap());

					self.symmetric_state.mix_key(&ee_key.as_bytes().to_vec());
				}

				Token::ES => {
					if self.initiator {
						let es_key =
							asymmetric::dh(&self.e.clone().unwrap(), &self.rs.clone().unwrap());

						self.symmetric_state.mix_key(&es_key.as_bytes().to_vec());
					} else {
						let es_key =
							asymmetric::dh(&self.s.clone().unwrap(), &self.re.clone().unwrap());

						self.symmetric_state.mix_key(&es_key.as_bytes().to_vec());
					}
				}

				Token::SE => {
					if self.initiator {
						let se_key =
							asymmetric::dh(&self.s.clone().unwrap(), &self.re.clone().unwrap());

						self.symmetric_state.mix_key(&se_key.as_bytes().to_vec());
					} else {
						let se_key =
							asymmetric::dh(&self.e.clone().unwrap(), &self.rs.clone().unwrap());

						self.symmetric_state.mix_key(&se_key.as_bytes().to_vec());
					}
				}

				Token::SS => {
					let ss_key =
						asymmetric::dh(&self.s.clone().unwrap(), &self.rs.clone().unwrap());

					self.symmetric_state.mix_key(&ss_key.as_bytes().to_vec());
				}

				Token::Psk => {
					let psk = self
						.psk
						.clone()
						.expect("disco: In processing psk token, no preshared key is set");
					self.symmetric_state.mix_key_and_hash(&psk);
				}
			}
		}

		let plaintext = self
			.symmetric_state
			.decrypt_and_hash(&msg)
			.map_err(|_| DiscoReadError::AuthErr)?;

		self.should_write = true;

		if self.message_patterns.len() == 0 {
			Ok((plaintext, true))
		} else {
			Ok((plaintext, false))
		}
	}
}
