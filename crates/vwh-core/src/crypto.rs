use crate::{Error, KeyFingerprint, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Sign bytes with Ed25519 signing key
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> [u8; 64] {
    let mut ctx = Vec::with_capacity(8 + message.len());
    ctx.extend_from_slice(b"vwh-v2\x00");
    ctx.extend_from_slice(message);
    let signature = signing_key.sign(&ctx);
    signature.to_bytes()
}

/// Verify Ed25519 signature
pub fn verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| Error::KeyMalformed)?;

    let sig = Signature::from_bytes(signature);

    let mut ctx = Vec::with_capacity(8 + message.len());
    ctx.extend_from_slice(b"vwh-v2\x00");
    ctx.extend_from_slice(message);

    verifying_key
        .verify(&ctx, &sig)
        .map_err(|_| Error::SignatureInvalid)
}

/// Calculate fingerprint of a public key
pub fn fingerprint(public_key: &[u8; 32]) -> KeyFingerprint {
    KeyFingerprint::new(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn test_sign_and_verify() {
        let signing_key = test_signing_key();
        let public_key = signing_key.verifying_key().to_bytes();
        let message = b"test message";

        let signature = sign(&signing_key, message);
        assert!(verify(&public_key, message, &signature).is_ok());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let signing_key = test_signing_key();
        let public_key = signing_key.verifying_key().to_bytes();
        let message = b"test message";
        let wrong_signature = [0u8; 64];

        assert!(verify(&public_key, message, &wrong_signature).is_err());
    }

    #[test]
    fn test_verify_wrong_message() {
        let signing_key = test_signing_key();
        let public_key = signing_key.verifying_key().to_bytes();
        let message = b"test message";
        let wrong_message = b"wrong message";

        let signature = sign(&signing_key, message);
        assert!(verify(&public_key, wrong_message, &signature).is_err());
    }
}

