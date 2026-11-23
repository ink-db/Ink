//! Integration tests for LocalBackend role enforcement and operations across the public API.

use ink_browser::backend::Backend;
use ink_browser::error::BackendError;
use ink_browser::LocalBackend;
use ink_core::auth::Role;
use ink_core::{Keypair, Store};
use tempfile::tempdir;

#[test]
fn test_local_backend_role_enforcement_and_operations() {
    let dir = tempdir().expect("Failed to create tempdir");
    let admin_kp = Keypair::generate();
    let alice_kp = Keypair::generate();

    // 1. Initialize store and grant Alice Writer & Reader on "sales"
    let (mut store, _) =
        Store::init_with_admin(dir.path(), Some(admin_kp.clone())).expect("Init failed");

    store
        .grant(
            &admin_kp,
            alice_kp.public_key(),
            "alice",
            Role::Writer,
            vec!["sales".to_string()],
            None,
        )
        .expect("Grant writer failed");

    store
        .grant(
            &admin_kp,
            alice_kp.public_key(),
            "alice",
            Role::Reader,
            vec!["sales".to_string()],
            None,
        )
        .expect("Grant reader failed");

    drop(store);

    // 2. Open LocalBackend as Alice
    let alice_backend = LocalBackend::open(dir.path(), alice_kp.clone())
        .expect("Alice must be able to open database");

    assert!(!alice_backend.session_info().is_admin());
    assert!(!alice_backend.session_info().can_view_access());
    assert!(alice_backend.session_info().can_write("sales"));
    assert!(!alice_backend.session_info().can_write("payroll"));

    // 3. Alice appends to "sales" (authorized)
    let append_summary = alice_backend
        .append_record(
            "sales",
            serde_json::json!({ "customer": "Acme", "amount": 500 }),
        )
        .expect("Alice append on sales must succeed");
    assert!(append_summary.id > 0);

    // 4. Alice attempts append to "payroll" (unauthorized)
    let err_append = alice_backend
        .append_record(
            "payroll",
            serde_json::json!({ "employee": "Eve", "salary": 10000 }),
        )
        .expect_err("Alice append on payroll must be denied");
    assert!(matches!(err_append, BackendError::AccessDenied(_)));

    // 5. Alice reads page from "sales"
    let page = alice_backend
        .read_page("sales", None, None, 50, 0)
        .expect("Read page on sales must succeed");
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].parsed_data["customer"], "Acme");

    // 6. Alice attempts to inspect _ink_access (unauthorized)
    let access_err = alice_backend
        .list_access()
        .expect_err("Alice cannot list access");
    assert!(matches!(access_err, BackendError::AccessDenied(_)));

    // 7. Alice corrects record #append_summary.id (authorized)
    let corr_summary = alice_backend
        .correct_record(
            append_summary.id,
            serde_json::json!({ "customer": "Acme Corp", "amount": 550 }),
            "Corrected legal customer name",
        )
        .expect("Alice correct on sales must succeed");
    assert!(corr_summary.id > append_summary.id);

    // 8. History shows original and correction
    let history = alice_backend
        .get_history(append_summary.id)
        .expect("Get history must succeed");
    assert_eq!(history.len(), 2);
    assert!(!history[0].is_correction);
    assert!(history[1].is_correction);
    assert_eq!(history[1].correction_of, Some(append_summary.id));

    // 9. Verification
    let verify = alice_backend
        .verify(Some("sales"))
        .expect("Verify must succeed");
    assert!(verify.is_valid);
    assert!(verify.records_checked >= 2);

    drop(alice_backend);

    // 10. Open as Admin and verify list_access
    let admin_backend = LocalBackend::open(dir.path(), admin_kp).expect("Admin open must succeed");
    assert!(admin_backend.session_info().can_view_access());
    let grants = admin_backend.list_access().expect("Admin must list access");
    assert!(grants.len() >= 3); // Genesis admin + Alice writer + Alice reader
}
