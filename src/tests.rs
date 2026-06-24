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
fn test_decrypt_rejects_short_ciphertext() {
    let key = vec![0x42u8; 44];
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    let field = ItemField {
        label: String::new(),
        value: Some(vec![0x01, 0x02]),
        field_type: "password".to_string(),
        sensitive: 1,
    };

    let result = field.decrypt(&key, uuid);

    assert!(matches!(result, Err(VaultError::DecryptionError(_))));
}

#[test]
fn test_decrypt_rejects_invalid_hex_ciphertext() {
    let key = vec![0x42u8; 44];
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    let field = ItemField {
        label: String::new(),
        value: Some(b"abc".to_vec()),
        field_type: "password".to_string(),
        sensitive: 1,
    };

    let result = field.decrypt(&key, uuid);

    assert!(matches!(result, Err(VaultError::DecryptionError(_))));
}

#[test]
fn test_decrypt_rejects_invalid_uuid_and_auth_tag() {
    let key = vec![0x42u8; 44];
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    let encrypted = encrypt_field("secret", &key, uuid).unwrap();
    let field = ItemField {
        label: String::new(),
        value: Some(encrypted.into_bytes()),
        field_type: "password".to_string(),
        sensitive: 1,
    };

    let invalid_uuid = field.decrypt(&key, "not-a-uuid");
    assert!(matches!(invalid_uuid, Err(VaultError::DecryptionError(_))));

    let invalid_tag = ItemField {
        label: String::new(),
        value: Some(vec![0x42; 16]),
        field_type: "password".to_string(),
        sensitive: 1,
    };
    let result = invalid_tag.decrypt(&key, uuid);

    assert!(matches!(result, Err(VaultError::DecryptionError(_))));
}

#[test]
fn test_encrypt_field_invalid_key_length() {
    let short_key = vec![0x42u8; 20]; // Too short
    let uuid = "550e8400-e29b-41d4-a716-446655440000";

    let result = encrypt_field("test", &short_key, uuid);
    assert!(result.is_err());
}

#[test]
fn test_encrypt_field_invalid_uuid() {
    let key = vec![0x42u8; 44];

    let result = encrypt_field("test", &key, "not-a-uuid");

    assert!(matches!(result, Err(VaultError::DecryptionError(_))));
}

#[test]
fn test_format_column_value_variants() {
    use rusqlite::types::ValueRef;

    assert_eq!(Vault::format_column_value(ValueRef::Null), "NULL");
    assert_eq!(Vault::format_column_value(ValueRef::Integer(42)), "42");
    assert_eq!(Vault::format_column_value(ValueRef::Real(1.5)), "1.5");
    assert_eq!(
        Vault::format_column_value(ValueRef::Text(b"short")),
        "\"short\""
    );
    assert_eq!(
        Vault::format_column_value(ValueRef::Blob(&[1, 2, 3])),
        "<blob 3 bytes>"
    );

    let long_text = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    assert_eq!(
        Vault::format_column_value(ValueRef::Text(long_text)),
        "\"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX...\""
    );
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
fn test_read_methods_handle_null_and_text_values() {
    let vault = test_vault_with_schema();
    let text_key_uuid = "550e8400-e29b-41d4-a716-446655440001";
    let null_key_uuid = "550e8400-e29b-41d4-a716-446655440002";
    let integer_key_uuid = "550e8400-e29b-41d4-a716-446655440003";

    vault
        .conn
        .execute(
            "INSERT INTO item (uuid, created_at, meta_updated_at, field_updated_at, title, subtitle, note, icon, category, template, key, updated_at, last_used)
             VALUES (?, 100, 100, 100, 'A Text Key', NULL, '', '', 'login', 'login.default', 'plain-key', 100, 0)",
            [text_key_uuid],
        )
        .unwrap();
    vault
        .conn
        .execute(
            "INSERT INTO item (uuid, created_at, meta_updated_at, field_updated_at, title, subtitle, note, icon, category, template, key, updated_at, last_used)
             VALUES (?, 100, 100, 100, 'B Null Key', '', '', '', 'login', 'login.default', NULL, 100, 0)",
            [null_key_uuid],
        )
        .unwrap();
    vault
        .conn
        .execute(
            "INSERT INTO itemfield (item_uuid, item_field_uid, label, value, type, sensitive, deleted, historical, form_id, updated_at, value_updated_at, orde, wearable, history, initial, hash, strength, algo_version, expiry, excluded, pwned_check_time, extra)
             VALUES (?, 10, 'Empty', NULL, 'note', 0, 0, 1, '', 100, 100, 1, 0, '', '', '', -1, 1, 0, 0, 0, '')",
            [text_key_uuid],
        )
        .unwrap();
    vault
        .conn
        .execute(
            "INSERT INTO item (uuid, created_at, meta_updated_at, field_updated_at, title, subtitle, note, icon, category, template, key, updated_at, last_used)
             VALUES (?, 100, 100, 100, 'C Integer Key', '', '', '', 'login', 'login.default', 7, 100, 0)",
            [integer_key_uuid],
        )
        .unwrap();
    vault
        .conn
        .execute(
            "INSERT INTO itemfield (item_uuid, item_field_uid, label, value, type, sensitive, deleted, historical, form_id, updated_at, value_updated_at, orde, wearable, history, initial, hash, strength, algo_version, expiry, excluded, pwned_check_time, extra)
             VALUES (?, 10, 'Number', 7, 'number', 0, 0, 1, '', 100, 100, 1, 0, '', '', '', -1, 1, 0, 0, 0, '')",
            [integer_key_uuid],
        )
        .unwrap();

    let text_key_item = vault.find_item("Text Key").unwrap().unwrap();
    let text_key_by_uuid = vault.find_item_by_uuid(text_key_uuid).unwrap().unwrap();
    let null_key_item = vault.find_item("Null Key").unwrap().unwrap();
    let null_key_by_uuid = vault.find_item_by_uuid(null_key_uuid).unwrap().unwrap();
    let integer_key_item = vault.find_item("Integer Key").unwrap().unwrap();
    let integer_key_by_uuid = vault.find_item_by_uuid(integer_key_uuid).unwrap().unwrap();
    let fields = vault.get_fields(text_key_uuid).unwrap();
    let integer_fields = vault.get_fields(integer_key_uuid).unwrap();

    assert_eq!(text_key_item.key.as_deref(), Some("plain-key".as_bytes()));
    assert_eq!(
        text_key_by_uuid.key.as_deref(),
        Some("plain-key".as_bytes())
    );
    assert!(null_key_item.key.is_none());
    assert!(null_key_by_uuid.key.is_none());
    assert!(integer_key_item.key.is_none());
    assert!(integer_key_by_uuid.key.is_none());
    assert!(fields[0].value.is_none());
    assert!(integer_fields[0].value.is_none());
}

#[test]
fn test_dump_methods_return_schema_and_raw_rows() {
    let vault = test_vault_with_schema();
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    insert_test_item(&vault, uuid, &vec![0x42u8; 44]);
    vault
        .conn
        .execute(
            "INSERT INTO itemfield (item_uuid, item_field_uid, label, value, type, sensitive, deleted, historical, form_id, updated_at, value_updated_at, orde, wearable, history, initial, hash, strength, algo_version, expiry, excluded, pwned_check_time, extra)
             VALUES (?, 10, 'Username', ?, 'username', 0, 0, 1, '', 100, 100, 1, 0, '', '', '', -1, 1, 0, 0, 0, '')",
            rusqlite::params![uuid, b"testuser".to_vec()],
        )
        .unwrap();

    let schema = vault.dump_schema().unwrap();
    let item = vault.dump_raw_item("Item").unwrap();
    let missing_item = vault.dump_raw_item("Missing").unwrap();
    let fields = vault.dump_raw_fields(uuid).unwrap();

    assert!(schema.iter().any(|(name, _)| name == "item"));
    assert!(
        item.iter()
            .any(|(name, value)| name == "title" && value == "\"Item\"")
    );
    assert!(missing_item.is_empty());
    assert_eq!(fields.len(), 1);
    assert!(
        fields[0]
            .iter()
            .any(|(name, value)| name == "value" && value == "<blob 8 bytes>")
    );
}

#[test]
fn test_write_schema_rejects_missing_table() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        r#"
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
        "#,
    )
    .unwrap();
    let vault = Vault { conn };

    let result = vault.create_item("Missing Fields", "login", &[]);

    assert!(matches!(
        result,
        Err(VaultError::UnsupportedVaultFormat(message)) if message == "missing table: itemfield"
    ));
}

fn fixture_vault_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test_vault")
}

#[test]
fn test_open_fixture_and_rejects_invalid_metadata() {
    let vault = Vault::open(fixture_vault_path(), "test123");
    assert!(vault.is_ok());

    let path = std::env::temp_dir().join(format!(
        "enpass-vault-invalid-json-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("vault.json"), b"not-json").unwrap();

    let result = Vault::open(&path, "test123");

    std::fs::remove_dir_all(&path).unwrap();
    assert!(matches!(result, Err(VaultError::JsonError(_))));
}

#[test]
fn test_open_rejects_missing_json_and_missing_database() {
    let missing_json_path = std::env::temp_dir().join(format!(
        "enpass-vault-missing-json-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&missing_json_path).unwrap();

    let missing_json = Vault::open(&missing_json_path, "test123");

    std::fs::remove_dir_all(&missing_json_path).unwrap();
    assert!(matches!(missing_json, Err(VaultError::IoError(_))));

    let missing_db_path =
        std::env::temp_dir().join(format!("enpass-vault-missing-db-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&missing_db_path).unwrap();
    std::fs::write(
        missing_db_path.join("vault.json"),
        r#"{"kdf_iter":1000,"have_keyfile":0}"#,
    )
    .unwrap();

    let missing_db = Vault::open(&missing_db_path, "test123");

    std::fs::remove_dir_all(&missing_db_path).unwrap();
    assert!(matches!(missing_db, Err(VaultError::IoError(_))));
}

#[test]
fn test_read_methods_return_sql_errors_without_schema() {
    let vault = Vault {
        conn: Connection::open_in_memory().unwrap(),
    };

    assert!(matches!(
        vault.list_items(None),
        Err(VaultError::SqlError(_))
    ));
    assert!(matches!(
        vault.find_item("anything"),
        Err(VaultError::SqlError(_))
    ));
    assert!(matches!(
        vault.get_fields("missing"),
        Err(VaultError::SqlError(_))
    ));
    assert!(matches!(
        vault.search("anything"),
        Err(VaultError::SqlError(_))
    ));
    assert!(matches!(
        vault.get_categories(),
        Err(VaultError::SqlError(_))
    ));
    assert!(matches!(
        vault.dump_raw_item("anything"),
        Err(VaultError::SqlError(_))
    ));
    assert!(matches!(
        vault.dump_raw_fields("missing"),
        Err(VaultError::SqlError(_))
    ));
    assert!(matches!(
        vault.find_item_by_uuid("missing"),
        Err(VaultError::SqlError(_))
    ));
}

#[test]
fn test_read_methods_surface_row_decode_errors() {
    let vault = test_vault_with_schema();
    let uuid = "550e8400-e29b-41d4-a716-446655440010";
    vault
        .conn
        .execute(
            "INSERT INTO item (uuid, created_at, meta_updated_at, field_updated_at, title, subtitle, note, icon, category, template, key, updated_at, last_used)
             VALUES (?, 100, 100, 100, x'ff', x'ff', '', '', x'ff', 'login.default', x'ff', 100, 0)",
            [uuid],
        )
        .unwrap();
    vault
        .conn
        .execute(
            "INSERT INTO itemfield (item_uuid, item_field_uid, label, value, type, sensitive, deleted, historical, form_id, updated_at, value_updated_at, orde, wearable, history, initial, hash, strength, algo_version, expiry, excluded, pwned_check_time, extra)
             VALUES (?, 10, x'ff', 'value', x'ff', x'ff', 0, 1, '', 100, 100, 1, 0, '', '', '', -1, 1, 0, 0, 0, '')",
            [uuid],
        )
        .unwrap();

    assert!(matches!(
        vault.list_items(None),
        Err(VaultError::SqlError(_))
    ));
    assert!(matches!(vault.find_item(""), Err(VaultError::SqlError(_))));
    assert!(matches!(
        vault.find_item_by_uuid(uuid),
        Err(VaultError::SqlError(_))
    ));
    assert!(matches!(
        vault.get_fields(uuid),
        Err(VaultError::SqlError(_))
    ));
    assert!(matches!(
        vault.search("value"),
        Err(VaultError::SqlError(_))
    ));
    assert!(matches!(
        vault.get_categories(),
        Err(VaultError::SqlError(_))
    ));
}

#[test]
fn test_item_key_errors_for_missing_item_and_missing_key() {
    let vault = test_vault_with_schema();
    let missing = vault.update_field(
        "550e8400-e29b-41d4-a716-446655440099",
        "password",
        "new-secret",
    );
    assert!(matches!(missing, Err(VaultError::DecryptionError(_))));

    let uuid = "550e8400-e29b-41d4-a716-446655440001";
    vault
        .conn
        .execute(
            "INSERT INTO item (uuid, created_at, meta_updated_at, field_updated_at, title, subtitle, note, icon, category, template, key, updated_at, last_used)
             VALUES (?, 100, 100, 100, 'No Key', '', '', '', 'login', 'login.default', NULL, 100, 0)",
            [uuid],
        )
        .unwrap();
    let no_key = vault.add_field(uuid, "password", "secret", true);

    assert!(matches!(no_key, Err(VaultError::DecryptionError(_))));
}

#[test]
fn test_in_memory_item_lifecycle_through_public_methods() {
    let vault = test_vault_with_schema();
    let uuid = vault
        .create_item(
            "Lifecycle Item",
            "login",
            &[
                ("username", "testuser", false),
                ("password", "secret", true),
            ],
        )
        .unwrap();

    let all_items = vault.list_items(None).unwrap();
    let login_items = vault.list_items(Some("login")).unwrap();
    let found_by_title = vault.find_item("Lifecycle").unwrap().unwrap();
    let found_by_uuid = vault.find_item_by_uuid(&uuid).unwrap().unwrap();
    let categories = vault.get_categories().unwrap();
    let search_results = vault.search("testuser").unwrap();

    assert_eq!(all_items.len(), 1);
    assert_eq!(login_items.len(), 1);
    assert_eq!(found_by_title.uuid, uuid);
    assert_eq!(found_by_uuid.title, "Lifecycle Item");
    assert_eq!(categories, vec!["login"]);
    assert_eq!(search_results.len(), 1);

    vault
        .add_field(&uuid, "url", "https://example.com", false)
        .unwrap();
    vault.add_field(&uuid, "totp", "123456", true).unwrap();
    vault
        .update_field(&uuid, "username", "updated-user")
        .unwrap();

    let item = vault.find_item_by_uuid(&uuid).unwrap().unwrap();
    let fields = vault.get_fields(&uuid).unwrap();
    let username = fields
        .iter()
        .find(|field| field.field_type == "username")
        .unwrap();
    let totp = fields
        .iter()
        .find(|field| field.field_type == "totp")
        .unwrap();

    assert_eq!(
        username.decrypt(item.key.as_ref().unwrap(), &uuid).unwrap(),
        "updated-user"
    );
    assert_eq!(
        totp.decrypt(item.key.as_ref().unwrap(), &uuid).unwrap(),
        "123456"
    );

    assert!(vault.remove_field(&uuid, "url").unwrap());
    vault.delete_item(&uuid).unwrap();

    let deleted_item = vault.find_item_by_uuid(&uuid).unwrap().unwrap();
    assert_eq!(deleted_item.trashed, 1);
    assert!(vault.list_items(None).unwrap().is_empty());
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

#[test]
fn test_create_item_surfaces_item_insert_errors() {
    let vault = test_vault_with_schema();
    vault
        .conn
        .execute_batch(
            r#"
            CREATE TRIGGER reject_item_insert
            BEFORE INSERT ON item
            BEGIN
                SELECT RAISE(ABORT, 'item insert rejected');
            END;
            "#,
        )
        .unwrap();

    let result = vault.create_item("Blocked", "login", &[]);

    assert!(matches!(result, Err(VaultError::SqlError(_))));
}

#[test]
fn test_create_item_surfaces_field_insert_errors() {
    let vault = test_vault_with_schema();
    vault
        .conn
        .execute_batch(
            r#"
            CREATE TRIGGER reject_itemfield_insert
            BEFORE INSERT ON itemfield
            BEGIN
                SELECT RAISE(ABORT, 'field insert rejected');
            END;
            "#,
        )
        .unwrap();

    let result = vault.create_item("Blocked Field", "login", &[("username", "user", false)]);

    assert!(matches!(result, Err(VaultError::SqlError(_))));
}

#[test]
fn test_add_field_surfaces_uid_query_type_errors() {
    let vault = test_vault_with_schema();
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    insert_test_item(&vault, uuid, &vec![0x42u8; 44]);
    vault
        .conn
        .execute(
            "INSERT INTO itemfield (item_uuid, item_field_uid, label, value, type, sensitive, deleted, historical, form_id, updated_at, value_updated_at, orde, wearable, history, initial, hash, strength, algo_version, expiry, excluded, pwned_check_time, extra)
             VALUES (?, 'not-a-number', '', 'value', 'username', 0, 0, 1, '', 100, 100, 1, 0, '', '', '', -1, 1, 0, 0, 0, '')",
            [uuid],
        )
        .unwrap();

    let result = vault.add_field(uuid, "url", "https://example.com", false);

    assert!(matches!(result, Err(VaultError::SqlError(_))));
}

#[test]
fn test_add_field_surfaces_order_query_type_errors() {
    let vault = test_vault_with_schema();
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    insert_test_item(&vault, uuid, &vec![0x42u8; 44]);
    vault
        .conn
        .execute(
            "INSERT INTO itemfield (item_uuid, item_field_uid, label, value, type, sensitive, deleted, historical, form_id, updated_at, value_updated_at, orde, wearable, history, initial, hash, strength, algo_version, expiry, excluded, pwned_check_time, extra)
             VALUES (?, 10, '', 'value', 'username', 0, 0, 1, '', 100, 100, 'not-a-number', 0, '', '', '', -1, 1, 0, 0, 0, '')",
            [uuid],
        )
        .unwrap();

    let result = vault.add_field(uuid, "url", "https://example.com", false);

    assert!(matches!(result, Err(VaultError::SqlError(_))));
}

#[test]
fn test_update_remove_and_delete_surface_trigger_errors() {
    let vault = test_vault_with_schema();
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    insert_test_item(&vault, uuid, &vec![0x42u8; 44]);
    vault.add_field(uuid, "username", "user", false).unwrap();

    vault
        .conn
        .execute_batch(
            r#"
            CREATE TRIGGER reject_itemfield_update
            BEFORE UPDATE ON itemfield
            BEGIN
                SELECT RAISE(ABORT, 'itemfield update rejected');
            END;
            "#,
        )
        .unwrap();

    let update_result = vault.update_field(uuid, "username", "updated");
    let remove_result = vault.remove_field(uuid, "username");

    vault
        .conn
        .execute_batch("DROP TRIGGER reject_itemfield_update;")
        .unwrap();
    vault
        .conn
        .execute_batch(
            r#"
            CREATE TRIGGER reject_item_update
            BEFORE UPDATE ON item
            BEGIN
                SELECT RAISE(ABORT, 'item update rejected');
            END;
            "#,
        )
        .unwrap();
    let delete_result = vault.delete_item(uuid);

    assert!(matches!(update_result, Err(VaultError::SqlError(_))));
    assert!(matches!(remove_result, Err(VaultError::SqlError(_))));
    assert!(matches!(delete_result, Err(VaultError::SqlError(_))));
}
