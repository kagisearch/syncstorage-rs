use std::collections::HashMap;
use actix_web::{Error, FromRequest, HttpRequest, dev::Payload, web::Data, http::Uri};
use futures::future::{LocalBoxFuture};

use syncserver_common::{Metrics, Taggable};
use syncstorage_db::UserIdentifier;
use tokenserver_auth::{TokenserverOrigin};

use crate::{
    error::{ApiError, ApiErrorKind},
    web::error::{ValidationErrorKind},
    web::extractors::{RequestErrorLocation},
    tokenserver::extractors::{Token, KeyId, JwtWorker},
    server::{MetricsWrapper}
};

pub struct JwtAuthData {
    pub client_state: String,
    pub email: String,
    pub user_id: UserIdentifier,
    pub role: String,
    pub generation: Option<i64>,
    pub keys_changed_at: Option<i64>,
    pub tokenserver_origin: TokenserverOrigin,
    pub metrics: Metrics,
}

impl JwtAuthData {
    fn uid_from_path(uri: &Uri) -> Result<u64, Error> {
        //TODO we could use this instead:
        //let path = req.match_info()
        //path.get("uid")
        let uid_str = uri.path().split("/").nth(2).unwrap_or("");//0 element is an empty string.

        if uid_str.is_empty() {
            return Err(ValidationErrorKind::FromDetails(
                "Missing UID".to_owned(),
                RequestErrorLocation::Path,
                Some("uid".to_owned()),
                Some("request.validate.url.missing_uid"),
            ))?;
        }

        match uid_str.parse::<u64>() {
            Ok(uid) => Ok(uid),
            Err(_) => {
                Err(ValidationErrorKind::FromDetails(
                "Invalid UID".to_owned(),
                RequestErrorLocation::Path,
                Some("uid".to_owned()),
                Some("request.validate.url.invalid_uid"),
            ))?
            }
        }
    }

}

impl FromRequest for JwtAuthData {
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let req = req.clone();

        Box::pin(async move {
            let token = Token::extract(&req).await?;
            let state = get_server_state(&req)?.as_ref();
 
            // The Python Tokenserver treats zero values and null values both as being
            // null, so for consistency, we need to convert a `Some(0)` value to `None`
            fn convert_zero_to_none(generation_or_keys_changed_at: Option<i64>) -> Option<i64> {
                match generation_or_keys_changed_at {
                    Some(0) => None,
                    _ => generation_or_keys_changed_at,
                }
            }

            match token {
                Token::JWT(token) => {
                    // Add a tag to the request extensions
                    req.add_tag("token_type".to_owned(), "OAuth".to_owned());

                    // Start a timer with the same tag
                    let mut tags = HashMap::default();
                    tags.insert("token_type".to_owned(), "OAuth".to_owned());
                    let mut metrics = MetricsWrapper::extract(&req).await?.0;
                    metrics.start_timer("token_verification", Some(tags));
                    //create the verifier at the boot strap time only if the jwk is available ,
                    //otherwise create it here after we've loaded the keys from the remote server
                    //using the get_remote_jwks from VerifyToken and move this method to JwtAuthData impl
                    let worker = Box::new(JwtWorker::new())
                        .expect("failed to create JwtWorker");
                    let verify_output = worker.verify_token(&state, &token, &metrics).await?;

                    // For requests using OAuth, the keys_changed_at and client state are embedded
                    // in the X-KeyID header.
                    let key_id = KeyId::extract(&req).await?;
                    let uid = Self::uid_from_path(req.uri())?;
                    let user_id = UserIdentifier {
                        legacy_id: uid,
                        fxa_uid: verify_output.fxa_uid.clone(),
                        fxa_kid: format!("fxa_kid{}", verify_output.fxa_uid), //--- IGNORE ---
                        hashed_fxa_uid: format!("hashed_fxa_uid{}", verify_output.fxa_uid), //--- IGNORE ---
                        hashed_device_id: format!("hashed_device_id{}", verify_output.fxa_uid), //--- IGNORE ---
                    };
                    let fxa_uid = verify_output.fxa_uid;
                    let email = format!("{}@{}", fxa_uid, state.email_domain);

                    Ok(JwtAuthData {
                        client_state: key_id.client_state,
                        email,
                        user_id,
                        generation: convert_zero_to_none(verify_output.generation),
                        role: verify_output.role,
                        keys_changed_at: convert_zero_to_none(Some(key_id.keys_changed_at)),
                        metrics,
                        tokenserver_origin: TokenserverOrigin::Rust,
                    })
                }
            }
        })
    }

}

fn get_server_state(req: &HttpRequest) -> Result<&Data<crate::server::ServerState>, Error> {
    req.app_data::<Data<crate::server::ServerState>>()
        .ok_or_else(|| {
            let err: ApiError = ApiErrorKind::Internal("Server state not found in request extensions".to_owned()).into();
            err.into()
        })
}


