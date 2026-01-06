//! Create a test vault fixture for integration tests
//! Run with: cargo run --example create_test_vault

use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use rusqlite::Connection;
use sha2::Sha512;
use std::fs;
use std::path::Path;

const TEST_PASSWORD: &str = "test123";
const KDF_ITERATIONS: u32 = 1000; // Low for fast tests

fn main() {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test_vault");

    if fixtures_dir.exists() {
        fs::remove_dir_all(&fixtures_dir).expect("Failed to remove existing fixture");
    }
    fs::create_dir_all(&fixtures_dir).expect("Failed to create fixture directory");

    let db_path = fixtures_dir.join("vault.enpassdb");

    // Generate a random salt
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    // Derive key from password + salt using PBKDF2-SHA512
    let mut key = vec![0u8; 64];
    pbkdf2_hmac::<Sha512>(TEST_PASSWORD.as_bytes(), &salt, KDF_ITERATIONS, &mut key);
    let hex_key = hex::encode(&key[..32]);

    // Create encrypted database with our chosen salt and derived key
    let conn = Connection::open(&db_path).expect("Failed to open database");
    conn.pragma_update(None, "key", format!("x'{}'", hex_key)).expect("Failed to set key");
    conn.pragma_update(None, "cipher_compatibility", 3).expect("Failed to set compatibility");
    conn.pragma_update(None, "cipher_salt", format!("x'{}'", hex::encode(salt)))
        .expect("Failed to set salt");

    // Create schema
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

        CREATE INDEX idx_item_category ON item(category);
        CREATE INDEX idx_item_trashed ON item(trashed);
        CREATE INDEX idx_itemfield_item_uuid ON itemfield(item_uuid);
        "#,
    )
    .expect("Failed to create schema");

    // Create test items
    create_test_item(
        &conn,
        "Test Login",
        "login",
        &[
            ("username", "testuser", false),
            ("password", "secretpass123", true),
            ("url", "https://example.com", false),
        ],
    );

    create_test_item(
        &conn,
        "Another Login",
        "login",
        &[
            ("username", "user2", false),
            ("password", "pass456", true),
            ("url", "https://test.example.org", false),
        ],
    );

    create_test_item(
        &conn,
        "Credit Card",
        "creditcard",
        &[
            ("cardholder", "Test User", false),
            ("number", "4111111111111111", true),
            ("cvv", "123", true),
        ],
    );

    create_test_item(
        &conn,
        "Secure Note",
        "note",
        &[("text", "This is a secret note", true)],
    );

    drop(conn);

    // Create vault.json
    let vault_json = format!(
        r#"{{"kdf_iter": {}, "have_keyfile": 0, "vault_uuid": "test-vault-uuid"}}"#,
        KDF_ITERATIONS
    );
    fs::write(fixtures_dir.join("vault.json"), vault_json).expect("Failed to write vault.json");

    println!("Test vault created at: {}", fixtures_dir.display());
    println!("Password: {}", TEST_PASSWORD);
}

fn create_test_item(conn: &Connection, title: &str, category: &str, fields: &[(&str, &str, bool)]) {
    use sha1::{Digest, Sha1};

    let item_uuid = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Generate random 44-byte key
    let mut key = vec![0u8; 44];
    rand::thread_rng().fill_bytes(&mut key);

    let template = format!("{}.default", category);

    conn.execute(
        "INSERT INTO item (uuid, created_at, meta_updated_at, field_updated_at, title, subtitle, note, icon, category, template, key, updated_at, last_used)
         VALUES (?, ?, ?, ?, ?, '', '', '', ?, ?, ?, ?, 0)",
        rusqlite::params![item_uuid, now, now, now, title, category, template, key, now],
    )
    .expect("Failed to insert item");

    let base_uid = 10i64;

    for (idx, (field_type, value, sensitive)) in fields.iter().enumerate() {
        let field_value = if *sensitive {
            encrypt_field(value, &key, &item_uuid)
        } else {
            value.to_string()
        };

        let hash = if !value.is_empty() {
            let mut hasher = Sha1::new();
            hasher.update(value.as_bytes());
            hex::encode(hasher.finalize())
        } else {
            String::new()
        };

        let initial = if *sensitive && !value.is_empty() {
            value.chars().take(2).collect::<String>()
        } else {
            String::new()
        };

        conn.execute(
            "INSERT INTO itemfield (item_uuid, item_field_uid, label, value, type, sensitive, deleted, historical, form_id, updated_at, value_updated_at, orde, wearable, history, initial, hash, strength, algo_version, expiry, excluded, pwned_check_time, extra)
             VALUES (?, ?, '', ?, ?, ?, 0, 1, '', ?, ?, ?, 0, '', ?, ?, -1, 1, 0, 0, 0, '')",
            rusqlite::params![
                item_uuid,
                base_uid + idx as i64,
                field_value,
                field_type,
                if *sensitive { 1 } else { 0 },
                now,
                now,
                idx as i64 + 1,
                initial,
                hash,
            ],
        )
        .expect("Failed to insert field");
    }
}

fn encrypt_field(plaintext: &str, item_key: &[u8], uuid: &str) -> String {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    let aes_key = &item_key[0..32];
    let nonce_bytes = &item_key[32..44];

    let cipher = Aes256Gcm::new_from_slice(aes_key).unwrap();
    let nonce = Nonce::from_slice(nonce_bytes);

    let aad_hex = uuid.replace("-", "");
    let aad = hex::decode(&aad_hex).unwrap();

    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .unwrap();

    hex::encode(ciphertext)
}
