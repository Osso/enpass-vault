use super::*;

const TEST_SCHEMA_SQL: &str = r#"
    CREATE TABLE item (
        uuid TEXT PRIMARY KEY,
        created_at INTEGER,
        meta_updated_at INTEGER,
        field_updated_at INTEGER,
        title TEXT,
        subtitle TEXT,
        note TEXT,
        icon TEXT,
        category TEXT,
        template TEXT,
        key BLOB,
        updated_at INTEGER,
        last_used INTEGER,
        trashed INTEGER DEFAULT 0,
        deleted INTEGER DEFAULT 0,
        favorite INTEGER DEFAULT 0,
        auto_submit INTEGER DEFAULT 0
    );

    CREATE TABLE itemfield (
        item_uuid TEXT,
        item_field_uid INTEGER,
        label TEXT,
        value BLOB,
        type TEXT,
        sensitive INTEGER,
        deleted INTEGER DEFAULT 0,
        historical INTEGER DEFAULT 1,
        form_id TEXT,
        updated_at INTEGER,
        value_updated_at INTEGER,
        orde INTEGER,
        wearable INTEGER DEFAULT 0,
        history TEXT,
        initial TEXT,
        hash TEXT,
        strength INTEGER DEFAULT -1,
        algo_version INTEGER DEFAULT 1,
        expiry INTEGER DEFAULT 0,
        excluded INTEGER DEFAULT 0,
        pwned_check_time INTEGER DEFAULT 0,
        extra TEXT,
        PRIMARY KEY (item_uuid, item_field_uid)
    );
"#;

#[test]
fn test_key_derivation() {
    let key = derive_key("test", b"0123456789abcdef", 1000);
    assert_eq!(key.len(), 64);
}

#[test]
fn test_encryption_roundtrip() {
    // Create a 44-byte key (32 AES + 12 nonce)
    let key = vec![0x42u8; 44];
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    let plaintext = "secret password";

    let encrypted = encrypt_field(plaintext, &key, uuid).unwrap();
    assert_ne!(encrypted, plaintext);

    // Create a field to decrypt
    let field = ItemField {
        label: String::new(),
        value: Some(encrypted.into_bytes()),
        field_type: "password".to_string(),
        sensitive: 1,
    };

    let decrypted = field.decrypt(&key, uuid).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encryption_with_different_uuids() {
    let key = vec![0x42u8; 44];
    let uuid1 = "550e8400-e29b-41d4-a716-446655440000";
    let uuid2 = "660e8400-e29b-41d4-a716-446655440000";
    let plaintext = "secret";

    let encrypted1 = encrypt_field(plaintext, &key, uuid1).unwrap();
    let encrypted2 = encrypt_field(plaintext, &key, uuid2).unwrap();

    // Same plaintext with different UUIDs should produce different ciphertext
    // (UUID is used as AAD)
    assert_ne!(encrypted1, encrypted2);
}

#[test]
fn test_decrypt_non_sensitive_field() {
    let key = vec![0x42u8; 44];
    let uuid = "550e8400-e29b-41d4-a716-446655440000";

    let field = ItemField {
        label: String::new(),
        value: Some(b"plain text value".to_vec()),
        field_type: "url".to_string(),
        sensitive: 0,
    };

    let decrypted = field.decrypt(&key, uuid).unwrap();
    assert_eq!(decrypted, "plain text value");
}

#[test]
fn test_decrypt_empty_field() {
    let key = vec![0x42u8; 44];
    let uuid = "550e8400-e29b-41d4-a716-446655440000";

    let field = ItemField {
        label: String::new(),
        value: None,
        field_type: "note".to_string(),
        sensitive: 1,
    };

    let decrypted = field.decrypt(&key, uuid).unwrap();
    assert_eq!(decrypted, "");
}

#[test]
fn test_encrypt_field_invalid_key_length() {
    let short_key = vec![0x42u8; 20]; // Too short
    let uuid = "550e8400-e29b-41d4-a716-446655440000";

    let result = encrypt_field("test", &short_key, uuid);
    assert!(result.is_err());
}

#[test]
fn test_compute_field_hash() {
    assert_eq!(compute_field_hash(""), "");
    let h = compute_field_hash("hello");
    assert!(!h.is_empty());
    assert_eq!(h, compute_field_hash("hello"));
    assert_ne!(h, compute_field_hash("world"));
}

#[test]
fn test_compute_field_initial() {
    assert_eq!(compute_field_initial("hello", true), "he");
    assert_eq!(compute_field_initial("hello", false), "");
    assert_eq!(compute_field_initial("", true), "");
    assert_eq!(compute_field_initial("x", true), "x");
}

fn test_vault_with_schema() -> Vault {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(TEST_SCHEMA_SQL).unwrap();

    Vault { conn }
}

fn insert_test_item(vault: &Vault, uuid: &str, key: &[u8]) {
    vault
        .conn
        .execute(
            "INSERT INTO item (uuid, created_at, meta_updated_at, field_updated_at, title, subtitle, note, icon, category, template, key, updated_at, last_used)
             VALUES (?, 100, 100, 100, 'Item', '', '', '', 'login', 'login.default', ?, 100, 0)",
            rusqlite::params![uuid, key],
        )
        .unwrap();
}

#[test]
fn test_update_field_refreshes_format_metadata_and_preserves_unknown_columns() {
    let vault = test_vault_with_schema();
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    let key = vec![0x42u8; 44];
    insert_test_item(&vault, uuid, &key);

    vault
        .conn
        .execute(
            "INSERT INTO itemfield (item_uuid, item_field_uid, label, value, type, sensitive, deleted, historical, form_id, updated_at, value_updated_at, orde, wearable, history, initial, hash, strength, algo_version, expiry, excluded, pwned_check_time, extra)
             VALUES (?, 10, 'Password', ?, 'password', 1, 0, 1, 'login-form', 100, 100, 1, 0, '{\"old\":true}', 'ol', 'old-hash', -1, 1, 0, 0, 0, '{\"custom\":\"keep\"}')",
            rusqlite::params![uuid, encrypt_field("old-value", &key, uuid).unwrap()],
        )
        .unwrap();

    vault.update_field(uuid, "password", "new-secret").unwrap();

    let (value, hash, initial, history, extra, form_id): (Vec<u8>, String, String, String, String, String) =
        vault
            .conn
            .query_row(
                "SELECT value, hash, initial, history, extra, form_id FROM itemfield WHERE item_uuid = ? AND type = 'password'",
                [uuid],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();

    let field = ItemField {
        label: "Password".to_string(),
        value: Some(value),
        field_type: "password".to_string(),
        sensitive: 1,
    };
    assert_eq!(field.decrypt(&key, uuid).unwrap(), "new-secret");
    assert_eq!(hash, compute_field_hash("new-secret"));
    assert_eq!(initial, compute_field_initial("new-secret", true));
    assert_eq!(history, "{\"old\":true}");
    assert_eq!(extra, "{\"custom\":\"keep\"}");
    assert_eq!(form_id, "login-form");
}

#[test]
fn test_update_field_fails_for_missing_field_without_touching_item() {
    let vault = test_vault_with_schema();
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    insert_test_item(&vault, uuid, &vec![0x42u8; 44]);

    let result = vault.update_field(uuid, "password", "new-secret");

    assert!(matches!(result, Err(VaultError::ItemFieldNotFound { .. })));
    let updated_at: i64 = vault
        .conn
        .query_row(
            "SELECT updated_at FROM item WHERE uuid = ?",
            [uuid],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(updated_at, 100);
}

#[test]
fn test_update_field_rejects_incomplete_enpass_schema_before_writing() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        r#"
        CREATE TABLE item (
            uuid TEXT PRIMARY KEY,
            field_updated_at INTEGER,
            key BLOB,
            updated_at INTEGER
        );

        CREATE TABLE itemfield (
            item_uuid TEXT,
            value BLOB,
            type TEXT,
            sensitive INTEGER,
            deleted INTEGER DEFAULT 0
        );
        "#,
    )
    .unwrap();

    let vault = Vault { conn };
    let result = vault.update_field(
        "550e8400-e29b-41d4-a716-446655440000",
        "password",
        "new-secret",
    );

    assert!(matches!(
        result,
        Err(VaultError::UnsupportedVaultFormat { .. })
    ));
}
