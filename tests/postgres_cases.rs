use apme_api::cases::{CaseService, CaseServiceError};
use apme_interfaces::{
    cases::{
        CreateCaseCommand, EncryptedObjectReference, RetentionClass, RotateEncryptedObjectCommand,
        TransitionCaseCommand,
    },
    security::VerifiedSubject,
    CaseStatus,
};
use chrono::{TimeZone, Utc};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{env, sync::Arc};
use uuid::Uuid;

struct TestDatabase {
    admin: PgPool,
    pool: PgPool,
    schema: String,
}

impl TestDatabase {
    async fn create() -> Self {
        let database_url = env::var("TEST_DATABASE_URL")
            .or_else(|_| env::var("DATABASE_URL"))
            .unwrap_or_else(|_| "postgresql:///postgres".into());
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("PostgreSQL is required for the persistence canary");
        let schema = format!("apme_test_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("create schema {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let connection_schema = Arc::new(schema.clone());
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .after_connect(move |connection, _| {
                let schema = connection_schema.clone();
                Box::pin(async move {
                    sqlx::query(&format!("set search_path to {schema}, public"))
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&database_url)
            .await
            .unwrap();
        Self {
            admin,
            pool,
            schema,
        }
    }

    async fn reconnect(&self) -> PgPool {
        let database_url = env::var("TEST_DATABASE_URL")
            .or_else(|_| env::var("DATABASE_URL"))
            .unwrap_or_else(|_| "postgresql:///postgres".into());
        let connection_schema = Arc::new(self.schema.clone());
        PgPoolOptions::new()
            .max_connections(4)
            .after_connect(move |connection, _| {
                let schema = connection_schema.clone();
                Box::pin(async move {
                    sqlx::query(&format!("set search_path to {schema}, public"))
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&database_url)
            .await
            .unwrap()
    }

    async fn destroy(self) {
        self.pool.close().await;
        sqlx::query(&format!("drop schema {} cascade", self.schema))
            .execute(&self.admin)
            .await
            .unwrap();
        self.admin.close().await;
    }
}

fn command(reference: &str) -> CreateCaseCommand {
    CreateCaseCommand {
        title: "Concurrent Apostille Case".into(),
        summary: "Sanitized metadata only".into(),
        client_reference: reference.into(),
        destination_country: "Peru".into(),
        document_type: "birth_certificate".into(),
        next_action_due_at: None,
        retention_class: RetentionClass::Standard,
        retain_until: Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap(),
        encrypted_document: Some(EncryptedObjectReference {
            object_reference: "objects/tenant-a/ciphertext-42".into(),
            ciphertext_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            key_version: 7,
        }),
    }
}

#[tokio::test]
async fn tenant_persistence_concurrency_restart_retention_and_audit_canary() {
    let database = TestDatabase::create().await;
    let service = CaseService::from_pool(database.pool.clone());
    service.migrate().await.unwrap();

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    let organization_a = Uuid::new_v4();
    let organization_b = Uuid::new_v4();
    sqlx::query(
        "insert into apme_tenants(id, organization_id, display_name) \
         values ($1,$2,'Tenant A'),($3,$4,'Tenant B')",
    )
    .bind(tenant_a)
    .bind(organization_a)
    .bind(tenant_b)
    .bind(organization_b)
    .execute(&database.pool)
    .await
    .unwrap();
    sqlx::query(
        "insert into apme_tenant_memberships(tenant_id, shared_user_id, role) \
         values ($1,'shared-user-a','agent'),($2,'shared-user-b','administrator')",
    )
    .bind(tenant_a)
    .bind(tenant_b)
    .execute(&database.pool)
    .await
    .unwrap();

    let subject_a = VerifiedSubject {
        shared_user_id: "shared-user-a".into(),
        session_id: "session-a".into(),
    };
    let context_a = service.tenant_context(&subject_a, tenant_a).await.unwrap();
    assert!(matches!(
        service.tenant_context(&subject_a, tenant_b).await,
        Err(CaseServiceError::NotAuthorized)
    ));

    let create = command("CLIENT-42");
    let now = Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap();
    let first = service.create_case(&context_a, &subject_a, "create-42", &create, now);
    let retry = service.create_case(&context_a, &subject_a, "create-42", &create, now);
    let (first, retry) = tokio::join!(first, retry);
    let first = first.unwrap();
    let retry = retry.unwrap();
    assert_eq!(first.case.id, retry.case.id);
    assert_eq!(first.event.event_id, retry.event.event_id);
    assert_ne!(first.replayed, retry.replayed);
    let case_id = first.case.id;

    let case_count: i64 = sqlx::query_scalar("select count(*) from apme_cases")
        .fetch_one(&database.pool)
        .await
        .unwrap();
    let event_count: i64 = sqlx::query_scalar("select count(*) from apme_case_events")
        .fetch_one(&database.pool)
        .await
        .unwrap();
    assert_eq!((case_count, event_count), (1, 1));

    let conflicting = command("DIFFERENT-CLIENT");
    assert!(matches!(
        service
            .create_case(&context_a, &subject_a, "create-42", &conflicting, now)
            .await,
        Err(CaseServiceError::IdempotencyConflict)
    ));
    let unchanged_count: i64 = sqlx::query_scalar("select count(*) from apme_case_events")
        .fetch_one(&database.pool)
        .await
        .unwrap();
    assert_eq!(unchanged_count, 1);

    let transition = TransitionCaseCommand {
        expected_version: 1,
        to_status: CaseStatus::CollectingDocuments,
    };
    let left = service.transition_case(
        &context_a,
        &subject_a,
        case_id,
        "transition-left",
        &transition,
        now,
    );
    let right = service.transition_case(
        &context_a,
        &subject_a,
        case_id,
        "transition-right",
        &transition,
        now,
    );
    let (left, right) = tokio::join!(left, right);
    let successes = usize::from(left.is_ok()) + usize::from(right.is_ok());
    let stale = usize::from(matches!(left, Err(CaseServiceError::StaleVersion)))
        + usize::from(matches!(right, Err(CaseServiceError::StaleVersion)));
    assert_eq!((successes, stale), (1, 1));

    let rotation = RotateEncryptedObjectCommand {
        expected_version: 2,
        encrypted_document: EncryptedObjectReference {
            object_reference: "objects/tenant-a/ciphertext-42-v2".into(),
            ciphertext_sha256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .into(),
            key_version: 8,
        },
    };
    assert!(matches!(
        service
            .rotate_encrypted_object(&context_a, &subject_a, case_id, "rotate-42", &rotation, now)
            .await,
        Err(CaseServiceError::NotAuthorized)
    ));
    sqlx::query(
        "update apme_tenant_memberships set role = 'administrator' \
         where tenant_id = $1 and shared_user_id = $2",
    )
    .bind(tenant_a)
    .bind(&subject_a.shared_user_id)
    .execute(&database.pool)
    .await
    .unwrap();
    let admin_context_a = service.tenant_context(&subject_a, tenant_a).await.unwrap();
    let rotated = service
        .rotate_encrypted_object(
            &admin_context_a,
            &subject_a,
            case_id,
            "rotate-42",
            &rotation,
            now,
        )
        .await
        .unwrap();
    assert_eq!(rotated.case.version, 3);
    assert_eq!(rotated.event.event_type, "case.document_key_rotated");

    let reconnected = CaseService::from_pool(database.reconnect().await);
    let durable = reconnected
        .get_case(&admin_context_a, case_id)
        .await
        .unwrap();
    assert_eq!(durable.version, 3);
    assert_eq!(durable.status, CaseStatus::CollectingDocuments);
    let durable_document = durable.encrypted_document.unwrap();
    assert_eq!(
        durable_document.object_reference,
        "objects/tenant-a/ciphertext-42-v2"
    );
    assert_eq!(durable_document.key_version, 8);
    reconnected
        .record_access(&admin_context_a, &subject_a, case_id)
        .await
        .unwrap();
    assert!(reconnected.verify_case_audit(case_id).await.unwrap());
    assert!(reconnected.verify_tenant_audit(tenant_a).await.unwrap());

    let raw_document_columns: i64 = sqlx::query_scalar(
        "select count(*) from information_schema.columns \
         where table_schema = current_schema() and table_name like 'apme_%' \
         and (column_name like '%document_bytes%' or column_name like '%raw_payload%' \
              or column_name like '%presigned_url%')",
    )
    .fetch_one(&database.pool)
    .await
    .unwrap();
    assert_eq!(raw_document_columns, 0);

    let mut transaction = database.pool.begin().await.unwrap();
    sqlx::query(
        "update apme_case_events set payload = payload || '{\"tampered\":true}'::jsonb \
         where case_id = $1 and case_version = 1",
    )
    .bind(case_id)
    .execute(&mut *transaction)
    .await
    .unwrap();
    let modified_valid: bool = sqlx::query_scalar("select apme_verify_case_audit($1)")
        .bind(case_id)
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
    assert!(!modified_valid);
    transaction.rollback().await.unwrap();

    let mut transaction = database.pool.begin().await.unwrap();
    sqlx::query("delete from apme_case_events where case_id = $1 and case_version = 1")
        .bind(case_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
    let deleted_valid: bool = sqlx::query_scalar("select apme_verify_case_audit($1)")
        .bind(case_id)
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
    assert!(!deleted_valid);
    transaction.rollback().await.unwrap();

    let subject_b = VerifiedSubject {
        shared_user_id: "shared-user-b".into(),
        session_id: "session-b".into(),
    };
    let context_b = service.tenant_context(&subject_b, tenant_b).await.unwrap();
    let mut expiring = command("EXPIRING");
    expiring.retain_until = Utc.with_ymd_and_hms(2026, 8, 25, 0, 0, 0).unwrap();
    let expiring = service
        .create_case(&context_b, &subject_b, "expiring", &expiring, now)
        .await
        .unwrap();
    let mut held = command("LEGAL-HOLD");
    held.retain_until = Utc.with_ymd_and_hms(2026, 8, 25, 0, 0, 0).unwrap();
    held.retention_class = RetentionClass::LegalHoldEligible;
    let held = service
        .create_case(&context_b, &subject_b, "held", &held, now)
        .await
        .unwrap();
    sqlx::query("update apme_cases set legal_hold = true where id = $1 and tenant_id = $2")
        .bind(held.case.id)
        .bind(tenant_b)
        .execute(&database.pool)
        .await
        .unwrap();
    let affected = service
        .apply_retention(
            Utc.with_ymd_and_hms(2026, 8, 26, 0, 0, 0).unwrap(),
            "retention-worker",
        )
        .await
        .unwrap();
    assert_eq!(affected, 1);
    let deleted_reference: Option<String> =
        sqlx::query_scalar("select encrypted_object_reference from apme_cases where id = $1")
            .bind(expiring.case.id)
            .fetch_one(&database.pool)
            .await
            .unwrap();
    assert_eq!(deleted_reference, None);
    let held_reference: Option<String> =
        sqlx::query_scalar("select encrypted_object_reference from apme_cases where id = $1")
            .bind(held.case.id)
            .fetch_one(&database.pool)
            .await
            .unwrap();
    assert_eq!(
        held_reference.as_deref(),
        Some("objects/tenant-a/ciphertext-42")
    );

    database.destroy().await;
}
