use apme_interfaces::{
    cases::{
        CaseEventReceipt, CaseMutationResult, CreateCaseCommand, EncryptedObjectReference,
        PersistedCase, RetentionClass, RotateEncryptedObjectCommand, TransitionCaseCommand,
    },
    security::{TenantContext, TenantRole, VerifiedSubject},
    CaseStatus, TENANT_CASE_PERSISTENCE_MIGRATION,
};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::{env, time::Duration};
use uuid::Uuid;

#[derive(Clone)]
pub struct CaseService {
    pool: PgPool,
}

#[derive(Debug, thiserror::Error)]
pub enum CaseServiceError {
    #[error("not authorized")]
    NotAuthorized,
    #[error("case not found")]
    NotFound,
    #[error("idempotency key was reused with a different request")]
    IdempotencyConflict,
    #[error("case version is stale")]
    StaleVersion,
    #[error("case transition is invalid")]
    InvalidTransition,
    #[error("encryption key version must increase")]
    KeyVersionRollback,
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("persistence unavailable")]
    Storage(#[source] sqlx::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum CaseConfigError {
    #[error("required persistence setting DATABASE_URL is missing")]
    MissingDatabaseUrl,
    #[error("database connection failed")]
    Connect(#[source] sqlx::Error),
}

impl CaseService {
    pub async fn from_env() -> Result<Self, CaseConfigError> {
        let database_url = env::var("DATABASE_URL")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .ok_or(CaseConfigError::MissingDatabaseUrl)?;
        let pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(16)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&database_url)
            .await
            .map_err(CaseConfigError::Connect)?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), CaseServiceError> {
        sqlx::raw_sql(TENANT_CASE_PERSISTENCE_MIGRATION)
            .execute(&self.pool)
            .await
            .map_err(CaseServiceError::Storage)?;
        Ok(())
    }

    /// Product membership is authoritative here; no tenant or role is accepted
    /// from the Shared Auth identity.
    pub async fn tenant_context(
        &self,
        subject: &VerifiedSubject,
        tenant_id: Uuid,
    ) -> Result<TenantContext, CaseServiceError> {
        let row = sqlx::query(
            "select t.organization_id, m.role from apme_tenants t \
             join apme_tenant_memberships m on m.tenant_id = t.id \
             where t.id = $1 and m.shared_user_id = $2 and m.active",
        )
        .bind(tenant_id)
        .bind(&subject.shared_user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(CaseServiceError::Storage)?
        .ok_or(CaseServiceError::NotAuthorized)?;

        let role = match row.get::<&str, _>("role") {
            "viewer" => TenantRole::Viewer,
            "agent" => TenantRole::Agent,
            "administrator" => TenantRole::Administrator,
            _ => return Err(CaseServiceError::NotAuthorized),
        };
        Ok(TenantContext {
            tenant_id,
            organization_id: row.get("organization_id"),
            role,
        })
    }

    pub async fn list_cases(
        &self,
        context: &TenantContext,
    ) -> Result<Vec<PersistedCase>, CaseServiceError> {
        let rows = sqlx::query(CASE_SELECT_LIST)
            .bind(context.tenant_id)
            .fetch_all(&self.pool)
            .await
            .map_err(CaseServiceError::Storage)?;
        rows.iter().map(case_from_row).collect()
    }

    pub async fn get_case(
        &self,
        context: &TenantContext,
        case_id: Uuid,
    ) -> Result<PersistedCase, CaseServiceError> {
        let row = sqlx::query(CASE_SELECT_ONE)
            .bind(context.tenant_id)
            .bind(case_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(CaseServiceError::Storage)?
            .ok_or(CaseServiceError::NotFound)?;
        case_from_row(&row)
    }

    pub async fn record_access(
        &self,
        context: &TenantContext,
        subject: &VerifiedSubject,
        resource_id: Uuid,
    ) -> Result<(), CaseServiceError> {
        sqlx::query("select apme_append_audit($1, 'access', $2, 'case', $3, $4, '{}'::jsonb)")
            .bind(context.tenant_id)
            .bind(&subject.shared_user_id)
            .bind(resource_id)
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(CaseServiceError::Storage)?;
        Ok(())
    }

    pub async fn create_case(
        &self,
        context: &TenantContext,
        subject: &VerifiedSubject,
        idempotency_key: &str,
        command: &CreateCaseCommand,
        now: DateTime<Utc>,
    ) -> Result<CaseMutationResult, CaseServiceError> {
        require_mutator(context)?;
        validate_idempotency_key(idempotency_key)?;
        command
            .validate(now)
            .map_err(CaseServiceError::Validation)?;
        let request_hash = canonical_hash(&(1_u8, command))?;
        let document = command.encrypted_document.as_ref();
        let row = sqlx::query(
            "select case_id, case_version, event_id, encode(event_hash, 'hex') as event_hash, replayed \
             from apme_create_case($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
        )
        .bind(context.tenant_id)
        .bind(&subject.shared_user_id)
        .bind(idempotency_key)
        .bind(request_hash.as_slice())
        .bind(&command.title)
        .bind(&command.summary)
        .bind(&command.client_reference)
        .bind(&command.destination_country)
        .bind(&command.document_type)
        .bind(command.next_action_due_at)
        .bind(retention_name(command.retention_class))
        .bind(command.retain_until)
        .bind(document.map(|value| value.object_reference.as_str()))
        .bind(document.map(|value| value.ciphertext_sha256.as_str()))
        .bind(document.map(|value| value.key_version))
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sql_error)?;
        self.mutation_result(context, &row).await
    }

    pub async fn transition_case(
        &self,
        context: &TenantContext,
        subject: &VerifiedSubject,
        case_id: Uuid,
        idempotency_key: &str,
        command: &TransitionCaseCommand,
        now: DateTime<Utc>,
    ) -> Result<CaseMutationResult, CaseServiceError> {
        require_mutator(context)?;
        validate_idempotency_key(idempotency_key)?;
        if command.expected_version <= 0 {
            return Err(CaseServiceError::Validation(
                "expected_version must be positive".into(),
            ));
        }
        let request_hash = canonical_hash(&(1_u8, case_id, command))?;
        let row = sqlx::query(
            "select case_id, case_version, event_id, encode(event_hash, 'hex') as event_hash, replayed \
             from apme_transition_case($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(context.tenant_id)
        .bind(&subject.shared_user_id)
        .bind(case_id)
        .bind(command.expected_version)
        .bind(status_name(command.to_status))
        .bind(idempotency_key)
        .bind(request_hash.as_slice())
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sql_error)?;
        self.mutation_result(context, &row).await
    }

    pub async fn rotate_encrypted_object(
        &self,
        context: &TenantContext,
        subject: &VerifiedSubject,
        case_id: Uuid,
        idempotency_key: &str,
        command: &RotateEncryptedObjectCommand,
        now: DateTime<Utc>,
    ) -> Result<CaseMutationResult, CaseServiceError> {
        context
            .role
            .can_export_or_delete()
            .then_some(())
            .ok_or(CaseServiceError::NotAuthorized)?;
        validate_idempotency_key(idempotency_key)?;
        if command.expected_version <= 0 {
            return Err(CaseServiceError::Validation(
                "expected_version must be positive".into(),
            ));
        }
        command
            .encrypted_document
            .validate()
            .map_err(CaseServiceError::Validation)?;
        let request_hash = canonical_hash(&(1_u8, case_id, command))?;
        let document = &command.encrypted_document;
        let row = sqlx::query(
            "select case_id, case_version, event_id, encode(event_hash, 'hex') as event_hash, replayed \
             from apme_rotate_case_object($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(context.tenant_id)
        .bind(&subject.shared_user_id)
        .bind(case_id)
        .bind(command.expected_version)
        .bind(idempotency_key)
        .bind(request_hash.as_slice())
        .bind(&document.object_reference)
        .bind(&document.ciphertext_sha256)
        .bind(document.key_version)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sql_error)?;
        self.mutation_result(context, &row).await
    }

    pub async fn apply_retention(
        &self,
        now: DateTime<Utc>,
        actor: &str,
    ) -> Result<i64, CaseServiceError> {
        let affected = sqlx::query_scalar::<_, i64>("select apme_apply_retention($1, $2)")
            .bind(now)
            .bind(actor)
            .fetch_one(&self.pool)
            .await
            .map_err(CaseServiceError::Storage)?;
        Ok(affected)
    }

    pub async fn verify_case_audit(&self, case_id: Uuid) -> Result<bool, CaseServiceError> {
        sqlx::query_scalar("select apme_verify_case_audit($1)")
            .bind(case_id)
            .fetch_one(&self.pool)
            .await
            .map_err(CaseServiceError::Storage)
    }

    pub async fn verify_tenant_audit(&self, tenant_id: Uuid) -> Result<bool, CaseServiceError> {
        sqlx::query_scalar("select apme_verify_tenant_audit($1)")
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await
            .map_err(CaseServiceError::Storage)
    }

    async fn mutation_result(
        &self,
        context: &TenantContext,
        mutation: &sqlx::postgres::PgRow,
    ) -> Result<CaseMutationResult, CaseServiceError> {
        let case_id: Uuid = mutation.get("case_id");
        let event_id: Uuid = mutation.get("event_id");
        let case = self.get_case(context, case_id).await?;
        let event_row = sqlx::query(
            "select tenant_id, case_id, case_version, event_type, occurred_at \
             from apme_case_events where tenant_id = $1 and event_id = $2",
        )
        .bind(context.tenant_id)
        .bind(event_id)
        .fetch_one(&self.pool)
        .await
        .map_err(CaseServiceError::Storage)?;
        Ok(CaseMutationResult {
            case,
            event: CaseEventReceipt {
                event_id,
                tenant_id: event_row.get("tenant_id"),
                case_id: event_row.get("case_id"),
                case_version: event_row.get("case_version"),
                event_type: event_row.get("event_type"),
                occurred_at: event_row.get("occurred_at"),
                event_hash: mutation.get("event_hash"),
            },
            replayed: mutation.get("replayed"),
        })
    }
}

const CASE_SELECT_LIST: &str = "select id, tenant_id, version, title, summary, client_reference, \
    destination_country, document_type, next_action_due_at, status, retention_class, \
    retain_until, legal_hold, tombstoned_at, encrypted_object_reference, ciphertext_sha256, \
    object_key_version, created_at, updated_at from apme_cases \
    where tenant_id = $1 and tombstoned_at is null order by created_at desc, id";
const CASE_SELECT_ONE: &str = "select id, tenant_id, version, title, summary, client_reference, \
    destination_country, document_type, next_action_due_at, status, retention_class, \
    retain_until, legal_hold, tombstoned_at, encrypted_object_reference, ciphertext_sha256, \
    object_key_version, created_at, updated_at from apme_cases \
    where tenant_id = $1 and id = $2 and tombstoned_at is null";

fn case_from_row(row: &sqlx::postgres::PgRow) -> Result<PersistedCase, CaseServiceError> {
    let status = parse_status(row.get("status"))?;
    let retention_class = parse_retention(row.get("retention_class"))?;
    let object_reference: Option<String> = row.get("encrypted_object_reference");
    let ciphertext_sha256: Option<String> = row.get("ciphertext_sha256");
    let key_version: Option<i32> = row.get("object_key_version");
    let encrypted_document = match (object_reference, ciphertext_sha256, key_version) {
        (Some(object_reference), Some(ciphertext_sha256), Some(key_version)) => {
            Some(EncryptedObjectReference {
                object_reference,
                ciphertext_sha256,
                key_version,
            })
        }
        (None, None, None) => None,
        _ => {
            return Err(CaseServiceError::Validation(
                "incomplete encrypted object reference in persistence".into(),
            ))
        }
    };
    Ok(PersistedCase {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        version: row.get("version"),
        title: row.get("title"),
        summary: row.get("summary"),
        client_reference: row.get("client_reference"),
        destination_country: row.get("destination_country"),
        document_type: row.get("document_type"),
        next_action_due_at: row.get("next_action_due_at"),
        status,
        retention_class,
        retain_until: row.get("retain_until"),
        legal_hold: row.get("legal_hold"),
        tombstoned_at: row.get("tombstoned_at"),
        encrypted_document,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn canonical_hash<T: serde::Serialize>(value: &T) -> Result<[u8; 32], CaseServiceError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| CaseServiceError::Validation(error.to_string()))?;
    Ok(Sha256::digest(bytes).into())
}

fn validate_idempotency_key(value: &str) -> Result<(), CaseServiceError> {
    if value.is_empty() || value.len() > 200 || value.chars().any(char::is_control) {
        return Err(CaseServiceError::Validation(
            "Idempotency-Key must contain 1 through 200 visible characters".into(),
        ));
    }
    Ok(())
}

fn require_mutator(context: &TenantContext) -> Result<(), CaseServiceError> {
    context
        .role
        .can_create_or_transition()
        .then_some(())
        .ok_or(CaseServiceError::NotAuthorized)
}

fn parse_status(value: &str) -> Result<CaseStatus, CaseServiceError> {
    match value {
        "intake" => Ok(CaseStatus::Intake),
        "collecting_documents" => Ok(CaseStatus::CollectingDocuments),
        "review" => Ok(CaseStatus::Review),
        "submitted" => Ok(CaseStatus::Submitted),
        "completed" => Ok(CaseStatus::Completed),
        "closed" => Ok(CaseStatus::Closed),
        _ => Err(CaseServiceError::Validation(
            "unknown persisted case status".into(),
        )),
    }
}

fn status_name(value: CaseStatus) -> &'static str {
    match value {
        CaseStatus::Intake => "intake",
        CaseStatus::CollectingDocuments => "collecting_documents",
        CaseStatus::Review => "review",
        CaseStatus::Submitted => "submitted",
        CaseStatus::Completed => "completed",
        CaseStatus::Closed => "closed",
    }
}

fn parse_retention(value: &str) -> Result<RetentionClass, CaseServiceError> {
    match value {
        "standard" => Ok(RetentionClass::Standard),
        "extended" => Ok(RetentionClass::Extended),
        "legal_hold_eligible" => Ok(RetentionClass::LegalHoldEligible),
        _ => Err(CaseServiceError::Validation(
            "unknown persisted retention class".into(),
        )),
    }
}

fn retention_name(value: RetentionClass) -> &'static str {
    match value {
        RetentionClass::Standard => "standard",
        RetentionClass::Extended => "extended",
        RetentionClass::LegalHoldEligible => "legal_hold_eligible",
    }
}

fn map_sql_error(error: sqlx::Error) -> CaseServiceError {
    let message = error
        .as_database_error()
        .map(|value| value.message())
        .unwrap_or_default();
    if message.contains("APME_NOT_AUTHORIZED") {
        CaseServiceError::NotAuthorized
    } else if message.contains("APME_CASE_NOT_FOUND") {
        CaseServiceError::NotFound
    } else if message.contains("APME_IDEMPOTENCY_CONFLICT") {
        CaseServiceError::IdempotencyConflict
    } else if message.contains("APME_STALE_VERSION") {
        CaseServiceError::StaleVersion
    } else if message.contains("APME_INVALID_TRANSITION") {
        CaseServiceError::InvalidTransition
    } else if message.contains("APME_KEY_VERSION_ROLLBACK") {
        CaseServiceError::KeyVersionRollback
    } else if message.contains("APME_CASE_OBJECT_NOT_FOUND") {
        CaseServiceError::NotFound
    } else {
        CaseServiceError::Storage(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn viewer_cannot_mutate_but_agent_can() {
        let context = |role| TenantContext {
            tenant_id: Uuid::nil(),
            organization_id: Uuid::nil(),
            role,
        };
        assert!(require_mutator(&context(TenantRole::Viewer)).is_err());
        assert!(require_mutator(&context(TenantRole::Agent)).is_ok());
    }

    #[test]
    fn canonical_hash_is_repeatable_and_request_sensitive() {
        let first = canonical_hash(&(1_u8, "tenant", "request")).unwrap();
        let replay = canonical_hash(&(1_u8, "tenant", "request")).unwrap();
        let changed = canonical_hash(&(1_u8, "tenant", "changed")).unwrap();
        assert_eq!(first, replay);
        assert_ne!(first, changed);
    }

    #[test]
    fn idempotency_key_rejects_empty_control_or_oversized_values() {
        assert!(validate_idempotency_key("create-42").is_ok());
        assert!(validate_idempotency_key("").is_err());
        assert!(validate_idempotency_key("bad\nkey").is_err());
        assert!(validate_idempotency_key(&"a".repeat(201)).is_err());
    }

    #[test]
    fn case_selects_are_tenant_predicated() {
        assert!(CASE_SELECT_LIST.contains("tenant_id = $1"));
        assert!(CASE_SELECT_ONE.contains("tenant_id = $1 and id = $2"));
    }
}
