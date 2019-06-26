pub(crate) enum Token {
	E,
	S,
	ES,
	SE,
	SS,
	EE,
	Psk,
}

pub(crate) type MessagePattern = &'static [Token];

pub struct HandshakePattern {
	pub(crate) name: &'static [u8],
	pub(crate) pre_message_patterns: &'static [MessagePattern],
	pub(crate) message_patterns: &'static [MessagePattern],
}

//
// One-way handshake patterns
//

pub const NOISE_N: HandshakePattern = HandshakePattern {
	name: b"N",
	pre_message_patterns: &[
		&[],         // →
		&[Token::S], // ←
	],
	message_patterns: &[
		&[Token::E, Token::ES], // →
	],
};

pub const NOISE_K: HandshakePattern = HandshakePattern {
	name: b"K",
	pre_message_patterns: &[
		&[Token::S], // →
		&[Token::S], // ←
	],
	message_patterns: &[
		&[Token::E, Token::ES, Token::SS], // →
	],
};

pub const NOISE_X: HandshakePattern = HandshakePattern {
	name: b"X",
	pre_message_patterns: &[
		&[],         // →
		&[Token::S], // ←
	],
	message_patterns: &[
		&[Token::E, Token::ES, Token::S, Token::SS], // →
	],
};

//
// Interactive handshake patterns
//

pub const NOISE_NN: HandshakePattern = HandshakePattern {
	name: b"NN",
	pre_message_patterns: &[
		&[], // →
		&[], // ←
	],
	message_patterns: &[
		&[Token::E],            // →
		&[Token::E, Token::EE], // ←
	],
};

pub const NOISE_NK: HandshakePattern = HandshakePattern {
	name: b"NK",
	pre_message_patterns: &[
		&[],         // →
		&[Token::S], // ←
	],
	message_patterns: &[
		&[Token::E, Token::ES], // →
		&[Token::E, Token::EE], // ←
	],
};

pub const NOISE_NX: HandshakePattern = HandshakePattern {
	name: b"NX",
	pre_message_patterns: &[
		&[], // →
		&[], // ←
	],
	message_patterns: &[
		&[Token::E],                                 // →
		&[Token::E, Token::EE, Token::S, Token::ES], // ←
	],
};

pub const NOISE_KN: HandshakePattern = HandshakePattern {
	name: b"KN",
	pre_message_patterns: &[
		&[Token::S], // →
		&[],         // ←
	],
	message_patterns: &[
		&[Token::E],                       // →
		&[Token::E, Token::EE, Token::SE], // ←
	],
};

pub const NOISE_KK: HandshakePattern = HandshakePattern {
	name: b"KK",
	pre_message_patterns: &[
		&[Token::S], // →
		&[Token::S], // ←
	],
	message_patterns: &[
		&[Token::E, Token::ES, Token::SS], // →
		&[Token::E, Token::EE, Token::SE], // ←
	],
};

pub const NOISE_KX: HandshakePattern = HandshakePattern {
	name: b"KX",
	pre_message_patterns: &[
		&[Token::S], // →
		&[],         // ←
	],
	message_patterns: &[
		&[Token::E],                                            // →
		&[Token::E, Token::EE, Token::SE, Token::S, Token::ES], // ←
	],
};

pub const NOISE_XN: HandshakePattern = HandshakePattern {
	name: b"XN",
	pre_message_patterns: &[
		&[], // →
		&[], // ←
	],
	message_patterns: &[
		&[Token::E],            // →
		&[Token::E, Token::EE], // ←
		&[Token::S, Token::SE], // →
	],
};

pub const NOISE_XK: HandshakePattern = HandshakePattern {
	name: b"XK",
	pre_message_patterns: &[
		&[],         // →
		&[Token::S], // ←
	],
	message_patterns: &[
		&[Token::E, Token::ES], // →
		&[Token::E, Token::EE], // ←
		&[Token::S, Token::SE], // →
	],
};

pub const NOISE_XX: HandshakePattern = HandshakePattern {
	name: b"XX",
	pre_message_patterns: &[
		&[], // →
		&[], // ←
	],
	message_patterns: &[
		&[Token::E],                                 // →
		&[Token::E, Token::EE, Token::S, Token::ES], // ←
		&[Token::E, Token::SE],                      // →
	],
};

pub const NOISE_IN: HandshakePattern = HandshakePattern {
	name: b"IN",
	pre_message_patterns: &[
		&[], // →
		&[], // ←
	],
	message_patterns: &[
		&[Token::E, Token::S],             // →
		&[Token::E, Token::EE, Token::SE], // ←
	],
};

pub const NOISE_IK: HandshakePattern = HandshakePattern {
	name: b"IK",
	pre_message_patterns: &[
		&[],         // →
		&[Token::S], // ←
	],
	message_patterns: &[
		&[Token::E, Token::ES, Token::S, Token::SS], // →
		&[Token::E, Token::EE, Token::SE],           // ←
	],
};

pub const NOISE_IX: HandshakePattern = HandshakePattern {
	name: b"IX",
	pre_message_patterns: &[
		&[], // →
		&[], // ←
	],
	message_patterns: &[
		&[Token::E, Token::S],                                  // →
		&[Token::E, Token::EE, Token::SE, Token::S, Token::ES], // ←
	],
};
