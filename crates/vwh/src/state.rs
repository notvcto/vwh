use anyhow::{anyhow, Result};
use vwh_core::{format::Artifact, ArtifactState};
use vwh_core::format::{TypedArtifact, Draft, Signed, Sealed};

/// Validate that an artifact is in a draft state
pub fn require_draft(artifact: &Artifact) -> Result<()> {
    match artifact.state() {
        ArtifactState::Draft => Ok(()),
        ArtifactState::Signed => Err(anyhow!(
            "Artifact is already signed. Use 'unsign' first if you need to edit."
        )),
        ArtifactState::Sealed => Err(anyhow!(
            "Artifact is sealed and cannot be modified."
        )),
    }
}

/// Validate that an artifact is signed but not sealed
pub fn require_signed_unsealed(artifact: &Artifact) -> Result<()> {
    match artifact.state() {
        ArtifactState::Draft => Err(anyhow!(
            "Artifact is not signed. Use 'sign' first."
        )),
        ArtifactState::Signed => Ok(()),
        ArtifactState::Sealed => Err(anyhow!(
            "Artifact is already sealed and cannot be modified."
        )),
    }
}

/// Typed entry points — wrap a runtime-checked artifact in its compile-time state type.
pub fn require_typed_draft(artifact: Artifact) -> Result<TypedArtifact<Draft>> {
    TypedArtifact::<Draft>::new(artifact).map_err(|e| anyhow!(e))
}

pub fn require_typed_signed(artifact: Artifact) -> Result<TypedArtifact<Signed>> {
    TypedArtifact::<Signed>::new(artifact).map_err(|e| anyhow!(e))
}

pub fn require_typed_sealed(artifact: Artifact) -> Result<TypedArtifact<Sealed>> {
    TypedArtifact::<Sealed>::new(artifact).map_err(|e| anyhow!(e))
}


