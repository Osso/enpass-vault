use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use pbkdf2::pbkdf2_hmac;
use rusqlite::Connection;
use serde::Deserialize;
use sha2::Sha512;
use std::fs;
use std::path::Path;
use thiserror::Error;

mod format;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Failed to read file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid vault metadata: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Database error: {0}")]
    SqlError(#[from] rusqlite::Error),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("Invalid vault file")]
    InvalidVault,

    #[error("Keyfile-protected vaults not yet supported")]
    KeyfileNotSupported,

    #[error("Wrong password")]
    WrongPassword,

    #[error("Item field not found: item {item_uuid}, field {field_type}")]
    ItemFieldNotFound {
        item_uuid: String,
        field_type: String,
    },

    #[error("Unsupported vault format: {0}")]
    UnsupportedVaultFormat(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Deserialize)]
struct VaultInfo {
    kdf_iter: u32,
    #[serde(default)]
    have_keyfile: u8,
}

pub struct Vault {
    conn: Connection,
}

impl Vault {
    pub fn open(vault_path: impl AsRef<Path>, password: &str) -> Result<Self> {
        let vault_path = vault_path.as_ref();
        let db_path = vault_path.join("vault.enpassdb");
        let json_path = vault_path.join("vault.json");

        let json_content = fs::read_to_string(&json_path)?;
        let info: VaultInfo = serde_json::from_str(&json_content)?;

        if info.have_keyfile != 0 {
            return Err(VaultError::KeyfileNotSupported);
        }

        let db_bytes = fs::read(&db_path)?;
        if db_bytes.len() < 16 {
            return Err(VaultError::InvalidVault);
        }
        let salt = &db_bytes[0..16];

        let key = derive_key(password, salt, info.kdf_iter);
        let hex_key = hex::encode(&key[..32]);

        let conn = Connection::open(&db_path)?;

        conn.pragma_update(None, "key", format!("x'{}'", hex_key))?;
        conn.pragma_update(None, "cipher_compatibility", 3)?;

        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .map_err(|_| VaultError::WrongPassword)?;

        Ok(Self { conn })
    }

    pub fn list_items(&self, category: Option<&str>) -> Result<Vec<Item>> {
        let mut query = String::from(
            "SELECT uuid, title, subtitle, category, trashed, favorite
             FROM item WHERE trashed = 0",
        );

        if category.is_some() {
            query.push_str(" AND lower(category) = lower(?)");
        }
        query.push_str(" ORDER BY title");

        let mut stmt = self.conn.prepare(&query)?;

        let rows = if let Some(cat) = category {
            stmt.query([cat])?
        } else {
            stmt.query([])?
        };

        let items: Vec<Item> = rows
            .mapped(|row| {
                Ok(Item {
                    uuid: row.get(0)?,
                    title: row.get(1)?,
                    subtitle: row.get(2)?,
                    category: row.get(3)?,
                    trashed: row.get(4)?,
                    favorite: row.get(5)?,
                    key: None,
                })
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(items)
    }

    pub fn find_item(&self, title: &str) -> Result<Option<Item>> {
        use rusqlite::types::ValueRef;

        let mut stmt = self.conn.prepare(
            "SELECT uuid, title, subtitle, category, trashed, favorite, key
             FROM item
             WHERE lower(title) LIKE lower(?) AND trashed = 0
             ORDER BY title
             LIMIT 1",
        )?;

        let pattern = format!("%{}%", title);
        let mut rows = stmt.query([&pattern])?;

        if let Some(row) = rows.next()? {
            // Handle key as either Text or Blob
            let key: Option<Vec<u8>> = match row.get_ref(6)? {
                ValueRef::Null => None,
                ValueRef::Text(t) => Some(t.to_vec()),
                ValueRef::Blob(b) => Some(b.to_vec()),
                _ => None,
            };

            Ok(Some(Item {
                uuid: row.get(0)?,
                title: row.get(1)?,
                subtitle: row.get(2)?,
                category: row.get(3)?,
                trashed: row.get(4)?,
                favorite: row.get(5)?,
                key,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_fields(&self, item_uuid: &str) -> Result<Vec<ItemField>> {
        use rusqlite::types::ValueRef;

        let mut stmt = self.conn.prepare(
            "SELECT label, value, type, sensitive, deleted
             FROM itemfield
             WHERE item_uuid = ? AND deleted = 0
             ORDER BY label",
        )?;

        let fields: Vec<ItemField> = stmt
            .query([item_uuid])?
            .mapped(|row| {
                // Handle value as either Text or Blob
                let value: Option<Vec<u8>> = match row.get_ref(1)? {
                    ValueRef::Null => None,
                    ValueRef::Text(t) => Some(t.to_vec()),
                    ValueRef::Blob(b) => Some(b.to_vec()),
                    _ => None,
                };

                Ok(ItemField {
                    label: row.get(0)?,
                    value,
                    field_type: row.get(2)?,
                    sensitive: row.get(3)?,
                })
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(fields)
    }

    pub fn search(&self, query: &str) -> Result<Vec<Item>> {
        let pattern = format!("%{}%", query);
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT i.uuid, i.title, i.subtitle, i.category, i.trashed, i.favorite
             FROM item i
             LEFT JOIN itemfield f ON i.uuid = f.item_uuid
             WHERE i.trashed = 0 AND (
                 lower(i.title) LIKE lower(?) OR
                 lower(i.subtitle) LIKE lower(?) OR
                 lower(f.value) LIKE lower(?)
             )
             ORDER BY i.title",
        )?;

        let items: Vec<Item> = stmt
            .query([&pattern, &pattern, &pattern])?
            .mapped(|row| {
                Ok(Item {
                    uuid: row.get(0)?,
                    title: row.get(1)?,
                    subtitle: row.get(2)?,
                    category: row.get(3)?,
                    trashed: row.get(4)?,
                    favorite: row.get(5)?,
                    key: None,
                })
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(items)
    }

    pub fn get_categories(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT category FROM item WHERE trashed = 0 ORDER BY category")?;

        let categories: Vec<String> = stmt
            .query([])?
            .mapped(|row| row.get(0))
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(categories)
    }

    pub fn dump_schema(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name")?;

        let tables: Vec<(String, String)> = stmt
            .query([])?
            .mapped(|row| {
                Ok((
                    row.get(0)?,
                    row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                ))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(tables)
    }

    pub fn dump_raw_item(&self, title: &str) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT * FROM item WHERE lower(title) LIKE lower(?) AND trashed = 0 LIMIT 1",
        )?;
        let pattern = format!("%{}%", title);

        let column_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let mut rows = stmt.query([&pattern])?;

        let mut result = Vec::new();
        if let Some(row) = rows.next()? {
            for (i, name) in column_names.iter().enumerate() {
                let value = Self::format_column_value(row.get_ref(i)?);
                result.push((name.clone(), value));
            }
        }

        Ok(result)
    }

    fn format_column_value(val: rusqlite::types::ValueRef) -> String {
        use rusqlite::types::ValueRef;
        match val {
            ValueRef::Null => "NULL".to_string(),
            ValueRef::Integer(n) => n.to_string(),
            ValueRef::Real(f) => f.to_string(),
            ValueRef::Text(t) => {
                let s = String::from_utf8_lossy(t);
                if s.len() > 50 {
                    format!("\"{}...\"", &s[..50])
                } else {
                    format!("\"{}\"", s)
                }
            }
            ValueRef::Blob(b) => format!("<blob {} bytes>", b.len()),
        }
    }

    pub fn dump_raw_fields(&self, item_uuid: &str) -> Result<Vec<Vec<(String, String)>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM itemfield WHERE item_uuid = ?")?;

        let column_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let mut rows = stmt.query([item_uuid])?;

        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            let mut field_data = Vec::new();
            for (i, name) in column_names.iter().enumerate() {
                let value = Self::format_column_value(row.get_ref(i)?);
                field_data.push((name.clone(), value));
            }
            result.push(field_data);
        }

        Ok(result)
    }

    // Write operations

    pub fn update_field(&self, item_uuid: &str, field_type: &str, new_value: &str) -> Result<()> {
        format::ensure_supported_write_schema(&self.conn)?;
        let key = self.item_key(item_uuid)?;

        let sensitive = self.find_field_sensitivity(item_uuid, field_type)?;

        let value_to_store: Vec<u8> = if sensitive != 0 {
            encrypt_field(new_value, &key, item_uuid)?.into_bytes()
        } else {
            new_value.as_bytes().to_vec()
        };
        let hash = compute_field_hash(new_value);
        let initial = compute_field_initial(new_value, sensitive != 0);
        let now = unix_now();

        self.conn.execute(
            "UPDATE itemfield
             SET value = ?, hash = ?, initial = ?, updated_at = ?, value_updated_at = ?
             WHERE item_uuid = ? AND type = ? AND deleted = 0",
            rusqlite::params![
                value_to_store,
                hash,
                initial,
                now,
                now,
                item_uuid,
                field_type
            ],
        )?;

        self.touch_item(item_uuid, now)?;

        Ok(())
    }

    pub fn create_item(
        &self,
        title: &str,
        category: &str,
        fields: &[(&str, &str, bool)],
    ) -> Result<String> {
        use rand::RngCore;

        format::ensure_supported_write_schema(&self.conn)?;
        let item_uuid = uuid::Uuid::new_v4().to_string();
        let now = unix_now();

        let mut key = vec![0u8; 44];
        rand::thread_rng().fill_bytes(&mut key);

        let template = format!("{}.default", category);

        self.conn.execute(
            "INSERT INTO item (uuid, created_at, meta_updated_at, field_updated_at, title, subtitle, note, icon, category, template, key, updated_at, last_used)
             VALUES (?, ?, ?, ?, ?, '', '', '', ?, ?, ?, ?, 0)",
            rusqlite::params![item_uuid, now, now, now, title, category, template, key, now],
        )?;

        let base_uid = 10i64;

        for (idx, (field_type, value, sensitive)) in fields.iter().enumerate() {
            self.insert_field(
                &item_uuid,
                base_uid + idx as i64,
                field_type,
                value,
                *sensitive,
                &key,
                idx as i64 + 1,
                now,
            )?;
        }

        Ok(item_uuid)
    }

    pub fn add_field(
        &self,
        item_uuid: &str,
        field_type: &str,
        value: &str,
        sensitive: bool,
    ) -> Result<()> {
        format::ensure_supported_write_schema(&self.conn)?;
        let key = self.item_key(item_uuid)?;
        let now = unix_now();

        let max_uid: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(item_field_uid), 9) FROM itemfield WHERE item_uuid = ?",
            rusqlite::params![item_uuid],
            |row| row.get(0),
        )?;
        let new_uid = max_uid + 1;

        let max_orde: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(orde), 0) FROM itemfield WHERE item_uuid = ? AND deleted = 0",
            rusqlite::params![item_uuid],
            |row| row.get(0),
        )?;
        let new_orde = max_orde + 1;

        self.insert_field(
            item_uuid, new_uid, field_type, value, sensitive, &key, new_orde, now,
        )?;

        self.touch_item(item_uuid, now)?;

        Ok(())
    }

    pub fn remove_field(&self, item_uuid: &str, field_type: &str) -> Result<bool> {
        format::ensure_supported_write_schema(&self.conn)?;
        let now = unix_now();

        let rows_affected = self.conn.execute(
            "UPDATE itemfield SET deleted = 1, updated_at = ? WHERE item_uuid = ? AND type = ? AND deleted = 0",
            rusqlite::params![now, item_uuid, field_type],
        )?;

        if rows_affected > 0 {
            self.touch_item(item_uuid, now)?;
        }

        Ok(rows_affected > 0)
    }

    pub fn delete_item(&self, item_uuid: &str) -> Result<()> {
        format::ensure_supported_write_schema(&self.conn)?;
        let now = unix_now();

        self.conn.execute(
            "UPDATE item SET deleted = 1, trashed = 1, updated_at = ? WHERE uuid = ?",
            rusqlite::params![now, item_uuid],
        )?;

        Ok(())
    }

    pub fn find_item_by_uuid(&self, uuid: &str) -> Result<Option<Item>> {
        use rusqlite::types::ValueRef;

        let mut stmt = self.conn.prepare(
            "SELECT uuid, title, subtitle, category, trashed, favorite, key
             FROM item WHERE uuid = ?",
        )?;

        let mut rows = stmt.query([uuid])?;

        if let Some(row) = rows.next()? {
            let key: Option<Vec<u8>> = match row.get_ref(6)? {
                ValueRef::Null => None,
                ValueRef::Text(t) => Some(t.to_vec()),
                ValueRef::Blob(b) => Some(b.to_vec()),
                _ => None,
            };

            Ok(Some(Item {
                uuid: row.get(0)?,
                title: row.get(1)?,
                subtitle: row.get(2)?,
                category: row.get(3)?,
                trashed: row.get(4)?,
                favorite: row.get(5)?,
                key,
            }))
        } else {
            Ok(None)
        }
    }

    fn item_key(&self, item_uuid: &str) -> Result<Vec<u8>> {
        let item = self
            .find_item_by_uuid(item_uuid)?
            .ok_or_else(|| VaultError::DecryptionError("Item not found".into()))?;
        item.key
            .ok_or_else(|| VaultError::DecryptionError("Item has no encryption key".into()))
    }

    fn find_field_sensitivity(&self, item_uuid: &str, field_type: &str) -> Result<i32> {
        let result = self.conn.query_row(
            "SELECT sensitive FROM itemfield WHERE item_uuid = ? AND type = ? AND deleted = 0",
            rusqlite::params![item_uuid, field_type],
            |row| row.get(0),
        );

        match result {
            Ok(sensitive) => Ok(sensitive),
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(VaultError::ItemFieldNotFound {
                item_uuid: item_uuid.to_string(),
                field_type: field_type.to_string(),
            }),
            Err(error) => Err(VaultError::SqlError(error)),
        }
    }

    fn touch_item(&self, item_uuid: &str, now: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE item SET field_updated_at = ?, updated_at = ? WHERE uuid = ?",
            rusqlite::params![now, now, item_uuid],
        )?;
        Ok(())
    }

    fn insert_field(
        &self,
        item_uuid: &str,
        uid: i64,
        field_type: &str,
        value: &str,
        sensitive: bool,
        key: &[u8],
        orde: i64,
        now: i64,
    ) -> Result<()> {
        let field_value = prepare_field_value(value, sensitive, key, item_uuid)?;
        let hash = compute_field_hash(value);
        let initial = compute_field_initial(value, sensitive);

        self.conn.execute(
            "INSERT INTO itemfield (item_uuid, item_field_uid, label, value, type, sensitive, deleted, historical, form_id, updated_at, value_updated_at, orde, wearable, history, initial, hash, strength, algo_version, expiry, excluded, pwned_check_time, extra)
             VALUES (?, ?, '', ?, ?, ?, 0, 1, '', ?, ?, ?, 0, '', ?, ?, -1, 1, 0, 0, 0, '')",
            rusqlite::params![
                item_uuid,
                uid,
                field_value,
                field_type,
                if sensitive { 1 } else { 0 },
                now,
                now,
                orde,
                initial,
                hash,
            ],
        )?;

        Ok(())
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn compute_field_hash(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn compute_field_initial(value: &str, sensitive: bool) -> String {
    if sensitive && !value.is_empty() {
        value.chars().take(2).collect()
    } else {
        String::new()
    }
}

fn prepare_field_value(
    value: &str,
    sensitive: bool,
    key: &[u8],
    item_uuid: &str,
) -> Result<String> {
    if sensitive {
        encrypt_field(value, key, item_uuid)
    } else {
        Ok(value.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct Item {
    pub uuid: String,
    pub title: String,
    pub subtitle: Option<String>,
    pub category: String,
    pub trashed: i32,
    pub favorite: i32,
    pub key: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ItemField {
    pub label: String,
    pub value: Option<Vec<u8>>,
    pub field_type: String,
    pub sensitive: i32,
}

impl ItemField {
    pub fn decrypt(&self, item_key: &[u8], uuid: &str) -> Result<String> {
        let Some(value) = self.non_empty_value() else {
            return Ok(String::new());
        };

        if self.sensitive == 0 {
            return Ok(String::from_utf8_lossy(value).to_string());
        }

        validate_item_key_len(item_key)?;
        let ciphertext = decode_ciphertext(value)?;
        decrypt_ciphertext(&ciphertext, item_key, uuid)
    }

    pub fn display_label(&self) -> &str {
        if self.label.is_empty() {
            &self.field_type
        } else {
            &self.label
        }
    }

    fn non_empty_value(&self) -> Option<&[u8]> {
        self.value.as_deref().filter(|value| !value.is_empty())
    }
}

fn encrypt_field(plaintext: &str, item_key: &[u8], uuid: &str) -> Result<String> {
    use aes_gcm::aead::Aead;

    validate_item_key_len(item_key)?;

    let aes_key = &item_key[0..32];
    let nonce_bytes = &item_key[32..44];

    let cipher = Aes256Gcm::new_from_slice(aes_key)
        .map_err(|e| VaultError::DecryptionError(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let aad = decode_aad(uuid)?;

    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|e| VaultError::DecryptionError(e.to_string()))?;

    Ok(hex::encode(ciphertext))
}

fn validate_item_key_len(item_key: &[u8]) -> Result<()> {
    if item_key.len() >= 44 {
        return Ok(());
    }

    Err(VaultError::DecryptionError(format!(
        "Invalid item key length: {}",
        item_key.len()
    )))
}

fn decode_ciphertext(value: &[u8]) -> Result<Vec<u8>> {
    let ciphertext = if value.iter().all(|b| b.is_ascii_hexdigit()) {
        let hex_str = String::from_utf8_lossy(value);
        hex::decode(hex_str.as_ref())
            .map_err(|e| VaultError::DecryptionError(format!("Hex decode error: {}", e)))?
    } else {
        value.to_vec()
    };

    if ciphertext.len() < 16 {
        return Err(VaultError::DecryptionError(
            "Encrypted value too short".into(),
        ));
    }

    Ok(ciphertext)
}

fn decrypt_ciphertext(ciphertext: &[u8], item_key: &[u8], uuid: &str) -> Result<String> {
    let aes_key = &item_key[0..32];
    let nonce_bytes = &item_key[32..44];
    let cipher = Aes256Gcm::new_from_slice(aes_key)
        .map_err(|e| VaultError::DecryptionError(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let aad = decode_aad(uuid)?;

    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|e| VaultError::DecryptionError(e.to_string()))?;

    Ok(String::from_utf8_lossy(&plaintext).to_string())
}

fn decode_aad(uuid: &str) -> Result<Vec<u8>> {
    let aad_hex = uuid.replace("-", "");
    hex::decode(&aad_hex).map_err(|e| VaultError::DecryptionError(format!("AAD hex decode: {}", e)))
}

fn derive_key(password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut key = vec![0u8; 64];
    pbkdf2_hmac::<Sha512>(password.as_bytes(), salt, iterations, &mut key);
    key
}

#[cfg(test)]
mod tests;
