//! End-to-end integration tests for the Ink TCP server daemon and client library.

use ink_client::{ClientError, Connection};
use ink_core::{auth::Role, Keypair, Store};
use ink_server::TcpDaemon;
use tempfile::tempdir;

#[tokio::test]
async fn test_tcp_handshake_auth_append_and_query() {
    let dir = tempdir().unwrap();
    let admin_kp = Keypair::generate();
    let alice_kp = Keypair::generate();
    let bob_kp = Keypair::generate(); // unauthorized key

    // Initialize database with Genesis Admin
    let (mut store, _) = Store::init_with_admin(dir.path(), Some(admin_kp.clone())).unwrap();

    // Grant Alice permissions on "sales"
    store
        .grant(
            &admin_kp,
            alice_kp.public_key(),
            "alice",
            Role::Writer,
            vec!["sales".to_string()],
            None,
        )
        .unwrap();
    store
        .grant(
            &admin_kp,
            alice_kp.public_key(),
            "alice",
            Role::Reader,
            vec!["sales".to_string()],
            None,
        )
        .unwrap();

    // Start TCP daemon on ephemeral port
    let (addr, _server_task) = TcpDaemon::start(store, "127.0.0.1:0", 50)
        .await
        .expect("Failed to start TCP daemon");
    let addr_str = addr.to_string();

    // Test 1: Bob (unauthorized) handshake attempt is rejected with 0x0403 ACCESS_DENIED
    let bob_err = Connection::connect(&addr_str, &bob_kp, None)
        .await
        .err()
        .expect("Bob must be rejected");
    match bob_err {
        ClientError::AuthFailed { code, name, .. } => {
            assert_eq!(code, 0x0403);
            assert_eq!(name, "ACCESS_DENIED");
        }
        other => panic!("Expected AuthFailed(0x0403), got {:?}", other),
    }

    // Test 2: Alice (authorized) handshake succeeds
    let mut alice_conn = Connection::connect(&addr_str, &alice_kp, None)
        .await
        .expect("Alice should connect successfully");

    assert_ne!(alice_conn.session_id(), [0u8; 16]);
    assert_ne!(alice_conn.database_id(), [0u8; 16]);

    // Test 3: Ping
    let latency = alice_conn.ping().await.expect("Ping should succeed");
    assert!(latency.as_millis() < 1000);

    // Test 4: Two-Step remote signed append to authorized table
    let append_res = alice_conn
        .append(
            "sales",
            "{\"customer\": \"Acme Corp\", \"amount\": 1500, \"currency\": \"USD\"}",
        )
        .await
        .expect("Append should succeed");

    assert_eq!(append_res.record_id, 3); // Record #0 is genesis admin, #1 is writer grant, #2 is reader grant, #3 is first user record
    assert_eq!(append_res.record_hash.len(), 64);
    assert!(append_res.timestamp_us > 0);

    // Test 5: Query authorized table with IQL
    let query_res = alice_conn
        .query("READ FROM \"sales\" WHERE amount >= 1000")
        .await
        .expect("Query should succeed");

    assert_eq!(query_res.rows_returned, 1);
    assert_eq!(query_res.rows.len(), 1);
    let row = &query_res.rows[0];
    assert_eq!(row["id"], 3);
    assert_eq!(row["data"]["customer"], "Acme Corp");
    assert_eq!(row["data"]["amount"], 1500);

    // Test 6: Tree head retrieval
    let tree_head = alice_conn
        .get_tree_head("sales")
        .await
        .expect("Get tree head should succeed");
    assert_eq!(tree_head.tree_size, 4); // 4 total records: genesis, writer grant, reader grant, user append
    assert_ne!(tree_head.root_hash, [0u8; 32]);

    // Test 7: Inclusion proof retrieval
    let proof = alice_conn
        .get_proof("sales", 3)
        .await
        .expect("Get inclusion proof should succeed");
    assert_eq!(proof.record_id, 3);
    assert_eq!(proof.tree_size, 4);

    // Test 8: Alice attempts append to unauthorized table ("payroll")
    let unauthorized_append = alice_conn
        .append("payroll", "{\"employee\": \"Eve\", \"salary\": 9000}")
        .await;
    match unauthorized_append {
        Err(ClientError::AccessDenied(_)) => {}
        other => panic!("Expected AccessDenied, got {:?}", other),
    }

    // Test 9: Alice attempts query on unauthorized table ("payroll")
    let unauthorized_query = alice_conn.query("READ FROM \"payroll\"").await;
    match unauthorized_query {
        Err(ClientError::AccessDenied(_)) => {}
        other => panic!("Expected AccessDenied, got {:?}", other),
    }
}
