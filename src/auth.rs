use apme_interfaces::security::VerifiedSubject;
use axum::http::{header, HeaderMap};
use shared_auth_client::{Introspection, SharedAuthClient};
use shared_auth_lib::{AuthOutcome, Authority, AuthorityConfig, Guard, GuardConfig, Identity};
use std::{env, sync::Arc, time::Duration};

const MAX_INTROSPECTION_RESPONSE_BYTES: usize = 64 * 1024;
pub const CASES_READ_SCOPE: &str = "apme:cases:read";
pub const CASES_WRITE_SCOPE: &str = "apme:cases:write";

#[derive(Clone)]
pub struct AuthService {
    guard: Arc<Guard>,
    introspection: SharedAuthClient,
    issuer: Arc<str>,
    audience: Arc<str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    Unauthorized,
    Forbidden,
    Degraded,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthConfigError {
    #[error("required authentication setting {0} is missing")]
    Missing(&'static str),
    #[error("Shared Auth client configuration is invalid")]
    InvalidClient,
}

impl AuthService {
    pub fn from_env() -> Result<Self, AuthConfigError> {
        let base = required_env("SHARED_AUTH_BASE_URL")?;
        let issuer = required_env("SHARED_AUTH_ISSUER")?;
        let audience = required_env("SHARED_AUTH_AUDIENCE")?;
        let introspection_credential = required_env("SHARED_AUTH_INTROSPECTION_CREDENTIAL")?;
        let login_url =
            env::var("SHARED_AUTH_LOGIN_URL").unwrap_or_else(|_| "/auth/sign-in".into());

        let guard = Guard::new(GuardConfig {
            authority: AuthorityConfig {
                shared_auth_base: base.clone(),
                issuer: issuer.clone(),
                audience: audience.clone(),
                supabase_url: None,
                supabase_api_key: None,
                // Protected introspection uses its own client and credential below.
                introspect_secret: None,
                arm_timeout: Duration::from_secs(2),
            },
            supabase_project: None,
            login_url,
            race_deadline: Duration::from_secs(2),
            ..GuardConfig::default()
        });
        let introspection = SharedAuthClient::try_new(base)
            .map_err(|_| AuthConfigError::InvalidClient)?
            .with_max_response_bytes(MAX_INTROSPECTION_RESPONSE_BYTES)
            .with_service_credential(introspection_credential);

        Ok(Self {
            guard: Arc::new(guard),
            introspection,
            issuer: issuer.into(),
            audience: audience.into(),
        })
    }

    /// Authenticate a session for both HTTP and WebSocket handshakes.
    ///
    /// The bearer value is deliberately never returned, logged, or attached to
    /// an error. Local ES256/JWKS verification is followed by protected
    /// introspection so a revoked session fails immediately.
    #[tracing::instrument(name = "apme.authenticate", skip_all)]
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<VerifiedSubject, AuthFailure> {
        self.authenticate_with_scopes(headers, &[CASES_READ_SCOPE])
            .await
    }

    #[tracing::instrument(name = "apme.authenticate.scoped", skip_all)]
    pub async fn authenticate_with_scopes(
        &self,
        headers: &HeaderMap,
        required_scopes: &[&str],
    ) -> Result<VerifiedSubject, AuthFailure> {
        let bearer = bearer(headers).ok_or(AuthFailure::Unauthorized)?;
        let identity = match self.guard.check(headers).await {
            AuthOutcome::Authenticated {
                identity,
                authority: Authority::SharedAuth,
                ..
            } if !identity.is_sandboxed() => identity,
            AuthOutcome::Authenticated { .. } => return Err(AuthFailure::Forbidden),
            AuthOutcome::Anonymous | AuthOutcome::Unauthenticated => {
                return Err(AuthFailure::Unauthorized)
            }
            AuthOutcome::Degraded { .. } => return Err(AuthFailure::Degraded),
        };

        let introspection = self
            .introspection
            .introspect_with_requirements(bearer, &self.audience, required_scopes)
            .await
            .map_err(|_| AuthFailure::Degraded)?;
        validate_active_session(
            &identity,
            &introspection,
            &self.issuer,
            &self.audience,
            required_scopes,
            unix_now(),
        )
    }
}

fn required_env(name: &'static str) -> Result<String, AuthConfigError> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(AuthConfigError::Missing(name))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn validate_active_session(
    identity: &Identity,
    introspection: &Introspection,
    issuer: &str,
    audience: &str,
    required_scopes: &[&str],
    now: u64,
) -> Result<VerifiedSubject, AuthFailure> {
    let identity_session = identity
        .session_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(AuthFailure::Unauthorized)?;
    if !introspection.active
        || introspection.sub.as_deref() != Some(identity.shared_user_id.as_str())
        || introspection.iss.as_deref() != Some(issuer)
        || introspection.aud.as_deref() != Some(audience)
        || introspection.sid.as_deref() != Some(identity_session)
        || introspection.exp.is_none_or(|expires| expires <= now)
        || introspection.nbf.is_some_and(|not_before| not_before > now)
        || required_scopes
            .iter()
            .any(|required| !introspection.has_scope(required))
    {
        return Err(AuthFailure::Unauthorized);
    }

    Ok(VerifiedSubject {
        shared_user_id: identity.shared_user_id.clone(),
        session_id: identity_session.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            shared_user_id: "shared-user-42".into(),
            provider: "shared-auth".into(),
            provider_tenant: "default".into(),
            provider_subject: "provider-user-42".into(),
            project: None,
            supabase_user_id: None,
            session_id: Some("session-42".into()),
            email: None,
            email_verified: false,
            roles: vec![],
            amr: vec!["passkey".into()],
            acr: None,
            cred: None,
            authority: Authority::SharedAuth,
        }
    }

    fn introspection() -> Introspection {
        serde_json::from_value(serde_json::json!({
            "active": true,
            "sub": "shared-user-42",
            "iss": "https://auth.example",
            "aud": "apostille-me",
            "sid": "session-42",
            "nbf": 900,
            "exp": 1100,
            "scope": "apme:cases:read apme:cases:write"
        }))
        .unwrap()
    }

    #[test]
    fn active_exact_session_is_accepted() {
        let subject = validate_active_session(
            &identity(),
            &introspection(),
            "https://auth.example",
            "apostille-me",
            &[CASES_READ_SCOPE],
            1000,
        )
        .unwrap();
        assert_eq!(subject.shared_user_id, "shared-user-42");
        assert_eq!(subject.session_id, "session-42");
    }

    #[test]
    fn revoked_expired_or_wrong_session_fails_closed() {
        let mut revoked = introspection();
        revoked.active = false;
        assert_eq!(
            validate_active_session(
                &identity(),
                &revoked,
                "https://auth.example",
                "apostille-me",
                &[CASES_READ_SCOPE],
                1000
            ),
            Err(AuthFailure::Unauthorized)
        );

        let mut expired = introspection();
        expired.exp = Some(1000);
        assert_eq!(
            validate_active_session(
                &identity(),
                &expired,
                "https://auth.example",
                "apostille-me",
                &[CASES_READ_SCOPE],
                1000
            ),
            Err(AuthFailure::Unauthorized)
        );

        let mut wrong_session = introspection();
        wrong_session.sid = Some("other-session".into());
        assert_eq!(
            validate_active_session(
                &identity(),
                &wrong_session,
                "https://auth.example",
                "apostille-me",
                &[CASES_READ_SCOPE],
                1000
            ),
            Err(AuthFailure::Unauthorized)
        );
    }

    #[test]
    fn wrong_issuer_or_audience_fails_closed() {
        assert_eq!(
            validate_active_session(
                &identity(),
                &introspection(),
                "https://other.example",
                "apostille-me",
                &[CASES_READ_SCOPE],
                1000
            ),
            Err(AuthFailure::Unauthorized)
        );
        assert_eq!(
            validate_active_session(
                &identity(),
                &introspection(),
                "https://auth.example",
                "other-product",
                &[CASES_READ_SCOPE],
                1000
            ),
            Err(AuthFailure::Unauthorized)
        );
    }
}
