use rand::thread_rng;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

pub const DH_SIZE: usize = 32;

#[derive(Clone)]
pub struct KeyPair {
	private_key: StaticSecret,
	public_key: PublicKey,
}

impl KeyPair {
	pub fn gen() -> KeyPair {
		let mut rng = thread_rng();
		let private_key = StaticSecret::new(&mut rng);
		let public_key = PublicKey::from(&private_key);
		KeyPair {
			private_key,
			public_key,
		}
	}

	pub fn get_public_key(&self) -> PublicKey {
		self.public_key
	}
}

pub fn dh(key_pair: &KeyPair, public_key: &PublicKey) -> SharedSecret {
	key_pair.private_key.diffie_hellman(public_key)
}
