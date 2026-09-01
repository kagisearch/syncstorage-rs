use super::VerifyOutput;
use crate::VerifyToken;
use crate::crypto::{JWTVerifier, JWTVerifyError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use syncserver_common::Metrics;
use tokenserver_common::TokenserverError;

const SYNC_ROLE: &str = "kagi:sync";

#[derive(Serialize, Deserialize, Debug)]
struct ResourceAccess {
    roles: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenClaims {
    #[serde(rename = "sub")]
    user: String,
    resource_access: ResourceAccess,
}

impl TokenClaims {
    fn validate(self) -> Result<VerifyOutput, TokenserverError> {
        if !self.resource_access.roles.contains(&SYNC_ROLE.to_string()) {
            return Err(TokenserverError::invalid_credentials(
                "Unauthorized".to_string(),
            ));
        }
        Ok(self.into())
    }
}

impl From<TokenClaims> for VerifyOutput {
    fn from(value: TokenClaims) -> Self {
        Self {
            fxa_uid: value.user,
            role: value.resource_access.roles.join(" "),
            generation: None, //--- IGNORE ---
        }
    }
}

/// The verifier used to verify OAuth tokens.
#[derive(Clone)]
pub struct Verifier<J> {
    jwk_verifiers: Vec<J>,
}

impl<J> Verifier<J>
where
    J: JWTVerifier,
{
    pub fn new(jwk_verifiers: Vec<J>) -> Result<Self, TokenserverError> {
        Ok(Self {
            jwk_verifiers,
        })
    }

    fn verify_jwt_locally(
        &self,
        token: &Vec<u8>,
    ) -> Result<TokenClaims, JWTVerifyError> {
        if self.jwk_verifiers.is_empty() {
            return Err(JWTVerifyError::InvalidKey);
        }

        self.jwk_verifiers
            .iter()
            .find_map(|verifier| {
                match verifier.verify::<TokenClaims>(token) {
                    // If it's an invalid signature, it means our key was well formatted,
                    // but the signature was incorrect. Lets try another key if we have any
                    Err(JWTVerifyError::InvalidSignature) => None,
                    res => Some(res),
                }
            })
            // If there is nothing, it means all of our keys were well formatted, but none of them
            // were able to verify the signature, lets erturn a TrustError
            .ok_or(JWTVerifyError::TrustError)?
    }
}


#[async_trait]
impl<J> VerifyToken<J> for Verifier<J>
where
    J: JWTVerifier,
{
    type Output = VerifyOutput;

    fn is_valid(&self) -> bool {
        !self.jwk_verifiers.is_empty()
    }

    fn jwk_verifiers(&mut self, jwk_verifiers: Vec<J>)  {
        self.jwk_verifiers = jwk_verifiers;
    }

    /// Verifies an OAuth token. Returns `VerifyOutput` for valid tokens and a `TokenserverError`
    /// for invalid tokens.
    ///
    /// The verifier will first attempt to verify the token using FxA's public keys, which were
    /// provided as environment variables.
    ///
    /// If FxA's public keys were not supplied, then the verifier will query FxA's /v1/jwks
    /// endpoint to get the latest public keys.
    ///
    /// If verifying the tokens fails because the keys are
    /// invalid, or because the keys were valid but the tokens have changed their structure, then
    /// the verifier will fallback to hitting fxa's /v1/verify endpoint to verify instead. All
    /// other failures will be recorded as invalid credentials and will returns a generic "Unauthorized" message
    /// to the user
    async fn verify(
        &self,
        token: &Vec<u8>,
        metrics: &Metrics,
    ) -> Result<VerifyOutput, TokenserverError> {
        let claims = match self.verify_jwt_locally(token) {
            Ok(res) => res,
            Err(e) => {
                if e.is_reportable_err() {
                    metrics.incr(e.metric_label())
                }
                return Err(unauthorized_err_with_ctx(e))
                // Dont verify token remotely.
                // match e {
                //     JWTVerifyError::DecodingError | JWTVerifyError::InvalidKey => {
                //         self.remote_verify_token(&token).await?
                //     }
                //     e => return Err(unauthorized_err_with_ctx(e)),
                // }
            }
        };
        claims.validate()
    }
}

fn unauthorized_err_with_ctx<E: std::fmt::Display>(err: E) -> TokenserverError {
    TokenserverError {
        context: "Unauthorized".to_string(),
        ..TokenserverError::invalid_credentials(err.to_string())
    }
}
