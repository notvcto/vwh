use crate::{crypto, format::Artifact, Result};

/// Verify artifact signature
pub fn verify_artifact(artifact: &Artifact) -> Result<()> {
    let signing_bytes = artifact.signing_bytes();
    crypto::verify(&artifact.author_pubkey, &signing_bytes, &artifact.signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{ArtifactBuilder, VERSION};
    use crate::{crypto, Intent};
    use chrono::Utc;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_verify_valid_artifact() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();

        let builder = ArtifactBuilder::new(Intent::Lab, public_key);
        let unsigned = builder.build_unsigned();
        let signing_bytes = unsigned.signing_bytes();
        let signature = crypto::sign(&signing_key, &signing_bytes);
        let artifact = unsigned.with_signature(signature);

        assert!(verify_artifact(&artifact).is_ok());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();

        let builder = ArtifactBuilder::new(Intent::Lab, public_key);
        let unsigned = builder.build_unsigned();
        let wrong_signature = [0u8; 64];
        let artifact = unsigned.with_signature(wrong_signature);

        assert!(verify_artifact(&artifact).is_err());
    }
}
