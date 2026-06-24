//! Create a test vault fixture for integration tests
//! Run with: cargo run --example create_test_vault

use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use rusqlite::Connection;
use sha2::Sha512;
use std::fs;
use std::path::{Path, PathBuf};

const TEST_PASSWORD: &str = "test123";
const KDF_ITERATIONS: u32 = 1000; // Low for fast tests
type RawField = (&'static str, &'static str, bool);

const SCHEMA_SQL: &str = r#"
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
"#;

const TEST_LOGIN_FIELDS: &[RawField] = &[
    ("username", "testuser", false),
    ("password", "secretpass123", true),
    ("url", "https://example.com", false),
];
const ANOTHER_LOGIN_FIELDS: &[RawField] = &[
    ("username", "user2", false),
    ("password", "pass456", true),
    ("url", "https://test.example.org", false),
];
const CREDIT_CARD_FIELDS: &[RawField] = &[
    ("cardholder", "Test User", false),
    ("number", "4111111111111111", true),
    ("cvv", "123", true),
];
const SECURE_NOTE_FIELDS: &[RawField] = &[("text", "This is a secret note", true)];

struct ItemSpec {
    title: &'static str,
    category: &'static str,
    fields: &'static [RawField],
}

const TEST_ITEMS: &[ItemSpec] = &[
    ItemSpec {
        title: "Test Login",
        category: "login",
        fields: TEST_LOGIN_FIELDS,
    },
    ItemSpec {
        title: "Another Login",
        category: "login",
        fields: ANOTHER_LOGIN_FIELDS,
    },
    ItemSpec {
        title: "Credit Card",
        category: "creditcard",
        fields: CREDIT_CARD_FIELDS,
    },
    ItemSpec {
        title: "Secure Note",
        category: "note",
        fields: SECURE_NOTE_FIELDS,
    },
];

fn main() {
    let fixtures_dir = prepare_fixture_dir();
    let db_path = fixtures_dir.join("vault.enpassdb");
    let salt = generate_salt();
    let hex_key = derive_hex_key(TEST_PASSWORD, &salt);
    let conn = open_encrypted_database(&db_path, &hex_key, &salt);

    create_schema(&conn);
    create_test_items(&conn);
    drop(conn);

    write_vault_json(&fixtures_dir);
    println!("Test vault created at: {}", fixtures_dir.display());
    println!("Password: {}", TEST_PASSWORD);
}

fn prepare_fixture_dir() -> PathBuf {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test_vault");

    if fixtures_dir.exists() {
        fs::remove_dir_all(&fixtures_dir).expect("Failed to remove existing fixture");
    }
    fs::create_dir_all(&fixtures_dir).expect("Failed to create fixture directory");

    fixtures_dir
}

fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

fn derive_hex_key(password: &str, salt: &[u8; 16]) -> String {
    let mut key = vec![0u8; 64];
    pbkdf2_hmac::<Sha512>(password.as_bytes(), salt, KDF_ITERATIONS, &mut key);
    hex::encode(&key[..32])
}

fn open_encrypted_database(db_path: &Path, hex_key: &str, salt: &[u8; 16]) -> Connection {
    let conn = Connection::open(db_path).expect("Failed to open database");
    conn.pragma_update(None, "key", format!("x'{}'", hex_key))
        .expect("Failed to set key");
    conn.pragma_update(None, "cipher_compatibility", 3)
        .expect("Failed to set compatibility");
    conn.pragma_update(None, "cipher_salt", format!("x'{}'", hex::encode(salt)))
        .expect("Failed to set salt");
    conn
}

fn create_schema(conn: &Connection) {
    conn.execute_batch(SCHEMA_SQL)
        .expect("Failed to create schema");
}

fn create_test_items(conn: &Connection) {
    for item in TEST_ITEMS {
        create_test_item(conn, item.title, item.category, item.fields);
    }
}

fn write_vault_json(fixtures_dir: &Path) {
    let vault_json = format!(
        r#"{{"kdf_iter": {}, "have_keyfile": 0, "vault_uuid": "test-vault-uuid"}}"#,
        KDF_ITERATIONS
    );
    fs::write(fixtures_dir.join("vault.json"), vault_json).expect("Failed to write vault.json");
}

fn create_test_item(conn: &Connection, title: &str, category: &str, fields: &[(&str, &str, bool)]) {
    let item_uuid = uuid::Uuid::new_v4().to_string();
    let now = current_unix_timestamp();
    let key = generate_item_key();
    let template = format!("{}.default", category);

    insert_item_row(conn, &item_uuid, now, title, category, &template, &key);
    insert_test_fields(conn, &item_uuid, fields, &key, now);
}

fn current_unix_timestamp() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("System clock before unix epoch")
        .as_secs();
    i64::try_from(secs).expect("Unix timestamp exceeded i64 range")
}

fn generate_item_key() -> Vec<u8> {
    let mut key = vec![0u8; 44];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

fn insert_item_row(
    conn: &Connection,
    item_uuid: &str,
    now: i64,
    title: &str,
    category: &str,
    template: &str,
    key: &[u8],
) {
    conn.execute(
        "INSERT INTO item (uuid, created_at, meta_updated_at, field_updated_at, title, subtitle, note, icon, category, template, key, updated_at, last_used)
         VALUES (?, ?, ?, ?, ?, '', '', '', ?, ?, ?, ?, 0)",
        rusqlite::params![item_uuid, now, now, now, title, category, template, key, now],
    )
    .expect("Failed to insert item");
}

fn insert_test_fields(
    conn: &Connection,
    item_uuid: &str,
    fields: &[(&str, &str, bool)],
    key: &[u8],
    now: i64,
) {
    let base_uid = 10i64;

    for (idx, (field_type, value, sensitive)) in fields.iter().enumerate() {
        let field = build_test_field(value, *sensitive, key, item_uuid);
        insert_field_row(
            conn,
            item_uuid,
            base_uid + idx as i64,
            field_type,
            *sensitive,
            now,
            idx as i64 + 1,
            &field,
        );
    }
}

struct TestField {
    value: String,
    initial: String,
    hash: String,
}

fn build_test_field(value: &str, sensitive: bool, key: &[u8], item_uuid: &str) -> TestField {
    let stored_value = if sensitive {
        encrypt_field(value, key, item_uuid)
    } else {
        value.to_string()
    };

    TestField {
        value: stored_value,
        initial: field_initial(value, sensitive),
        hash: field_hash(value),
    }
}

fn field_hash(value: &str) -> String {
    use sha1::{Digest, Sha1};

    if value.is_empty() {
        return String::new();
    }

    let mut hasher = Sha1::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn field_initial(value: &str, sensitive: bool) -> String {
    if sensitive && !value.is_empty() {
        value.chars().take(2).collect::<String>()
    } else {
        String::new()
    }
}

fn insert_field_row(
    conn: &Connection,
    item_uuid: &str,
    field_uid: i64,
    field_type: &str,
    sensitive: bool,
    now: i64,
    orde: i64,
    field: &TestField,
) {
    conn.execute(
        "INSERT INTO itemfield (item_uuid, item_field_uid, label, value, type, sensitive, deleted, historical, form_id, updated_at, value_updated_at, orde, wearable, history, initial, hash, strength, algo_version, expiry, excluded, pwned_check_time, extra)
         VALUES (?, ?, '', ?, ?, ?, 0, 1, '', ?, ?, ?, 0, '', ?, ?, -1, 1, 0, 0, 0, '')",
        rusqlite::params![
            item_uuid,
            field_uid,
            field.value,
            field_type,
            if sensitive { 1 } else { 0 },
            now,
            now,
            orde,
            field.initial,
            field.hash,
        ],
    )
    .expect("Failed to insert field");
}

fn encrypt_field(plaintext: &str, item_key: &[u8], uuid: &str) -> String {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};

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
