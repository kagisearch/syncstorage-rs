#[allow(dead_code)]
mod crypto;
#[cfg(any(test, feature = "test-support"))]
pub mod test_utils;

pub use crypto::{FxaWebhookClaims, JWTVerifyError, SETVerifierImpl};
#[cfg(not(feature = "py"))]
pub use crypto::{JWTVerifier, JWTVerifierImpl};

#[allow(clippy::result_large_err)]
pub mod oauth;
#[allow(clippy::result_large_err)]
mod token;
use syncserver_common::Metrics;
pub use token::Tokenlib;

use std::fmt;

use async_trait::async_trait;
use dyn_clone::{self, DynClone};
use serde::{Deserialize, Serialize};
use tokenserver_common::TokenserverError;
/// Represents the origin of the token used by Sync clients to access their data.
#[derive(Clone, Copy, Default, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenserverOrigin {
    /// The Python Tokenserver.
    #[default]
    Python,
    /// The Rust Tokenserver.
    Rust,
}

impl fmt::Display for TokenserverOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenserverOrigin::Python => write!(f, "python"),
            TokenserverOrigin::Rust => write!(f, "rust"),
        }
    }
}

/// The plaintext needed to build a token.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct MakeTokenPlaintext {
    pub node: String,
    pub fxa_kid: String,
    pub fxa_uid: String,
    pub hashed_device_id: String,
    pub hashed_fxa_uid: String,
    pub expires: u64,
    pub uid: i64,
    pub tokenserver_origin: TokenserverOrigin,
}

/// Implementers of this trait can be used to verify tokens for Tokenserver.
#[async_trait]
pub trait VerifyToken<P>: DynClone + Sync + Send {
    type Output: Clone;

    fn is_valid(&self) -> bool;

    fn jwk_verifiers(&mut self, jwk_verifiers: Vec<P>);

    /// Verifies the given token. This function is async because token verification often involves
    /// making a request to a remote server.
    async fn verify(
        &self,
        token: &Vec<u8>,
        metrics: &Metrics,
    ) -> Result<Self::Output, TokenserverError>;
}

dyn_clone::clone_trait_object!(<T,P> VerifyToken<P,Output=T>);

/// A mock verifier to be used for testing purposes.
#[derive(Clone, Default)]
pub struct MockVerifier<T: Clone + Send + Sync> {
    pub valid: bool,
    pub verify_output: T,
}

#[async_trait]
impl<T: Clone + Send + Sync> VerifyToken<JWTVerifierImpl> for MockVerifier<T> {
    type Output = T;

    fn is_valid(&self) -> bool {true}

    fn jwk_verifiers(&mut self, _jwk_verifiers: Vec<JWTVerifierImpl>) {

    }

    async fn verify(&self, _token: &Vec<u8>, _metrics: &Metrics) -> Result<T, TokenserverError> {
        self.valid
            .then(|| self.verify_output.clone())
            .ok_or_else(|| TokenserverError::invalid_credentials("Unauthorized".to_owned()))
    }
}
