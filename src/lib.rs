use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use rusqlite::Connection;
use serde::Deserialize;
use sha2::Sha512;
use std::fs;
use std::path::Path;
use thiserror::Error;

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
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT category FROM item WHERE trashed = 0 ORDER BY category",
        )?;

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

    /// Dump raw item data for debugging
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
                use rusqlite::types::ValueRef;
                let value = match row.get_ref(i)? {
                    ValueRef::Null => "NULL".to_string(),
                    ValueRef::Integer(n) => n.to_string(),
                    ValueRef::Real(f) => f.to_string(),
                    ValueRef::Text(t) => format!("\"{}\"", String::from_utf8_lossy(t)),
                    ValueRef::Blob(b) => format!("<blob {} bytes>", b.len()),
                };
                result.push((name.clone(), value));
            }
        }

        Ok(result)
    }

    /// Dump raw itemfield data for debugging
    pub fn dump_raw_fields(&self, item_uuid: &str) -> Result<Vec<Vec<(String, String)>>> {
        let mut stmt = self.conn.prepare(
            "SELECT * FROM itemfield WHERE item_uuid = ?",
        )?;

        let column_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let mut rows = stmt.query([item_uuid])?;

        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            let mut field_data = Vec::new();
            for (i, name) in column_names.iter().enumerate() {
                use rusqlite::types::ValueRef;
                let value = match row.get_ref(i)? {
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
                    },
                    ValueRef::Blob(b) => format!("<blob {} bytes>", b.len()),
                };
                field_data.push((name.clone(), value));
            }
            result.push(field_data);
        }

        Ok(result)
    }

    // Write operations

    /// Update a field's value for an existing item
    pub fn update_field(&self, item_uuid: &str, field_type: &str, new_value: &str) -> Result<()> {
        // Get the item to get its encryption key
        let item = self.find_item_by_uuid(item_uuid)?
            .ok_or_else(|| VaultError::DecryptionError("Item not found".into()))?;

        let key = item.key.as_ref()
            .ok_or_else(|| VaultError::DecryptionError("Item has no encryption key".into()))?;

        // Check if field is sensitive (needs encryption)
        let sensitive: i32 = self.conn.query_row(
            "SELECT sensitive FROM itemfield WHERE item_uuid = ? AND type = ? AND deleted = 0",
            rusqlite::params![item_uuid, field_type],
            |row| row.get(0),
        ).unwrap_or(1); // Default to sensitive if not found

        // Only encrypt if the field is sensitive
        let value_to_store: Vec<u8> = if sensitive != 0 {
            encrypt_field(new_value, key, item_uuid)?.into_bytes()
        } else {
            new_value.as_bytes().to_vec()
        };

        // Update the field
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        self.conn.execute(
            "UPDATE itemfield SET value = ?, updated_at = ?, value_updated_at = ?
             WHERE item_uuid = ? AND type = ? AND deleted = 0",
            rusqlite::params![value_to_store, now, now, item_uuid, field_type],
        )?;

        // Update item timestamps
        self.conn.execute(
            "UPDATE item SET field_updated_at = ?, updated_at = ? WHERE uuid = ?",
            rusqlite::params![now, now, item_uuid],
        )?;

        Ok(())
    }

    /// Create a new item with fields
    pub fn create_item(&self, title: &str, category: &str, fields: &[(&str, &str, bool)]) -> Result<String> {
        use rand::RngCore;

        let item_uuid = uuid::Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Generate random 44-byte key (32 AES + 12 nonce)
        let mut key = vec![0u8; 44];
        rand::thread_rng().fill_bytes(&mut key);

        // Template based on category
        let template = format!("{}.default", category);

        // Insert item with all required fields
        self.conn.execute(
            "INSERT INTO item (uuid, created_at, meta_updated_at, field_updated_at, title, subtitle, note, icon, category, template, key, updated_at, last_used)
             VALUES (?, ?, ?, ?, ?, '', '', '', ?, ?, ?, ?, 0)",
            rusqlite::params![item_uuid, now, now, now, title, category, template, key, now],
        )?;

        // Field UIDs should start at 10 like Enpass does
        let base_uid = 10i64;

        // Insert fields with all required columns
        for (idx, (field_type, value, sensitive)) in fields.iter().enumerate() {
            let field_value = if *sensitive {
                encrypt_field(value, &key, &item_uuid)?
            } else {
                value.to_string()
            };

            // Compute hash like Enpass does (SHA1 of value)
            let hash = if !value.is_empty() {
                use sha1::{Sha1, Digest};
                let mut hasher = Sha1::new();
                hasher.update(value.as_bytes());
                hex::encode(hasher.finalize())
            } else {
                String::new()
            };

            // Initial is first 2 chars for sensitive fields
            let initial = if *sensitive && !value.is_empty() {
                value.chars().take(2).collect::<String>()
            } else {
                String::new()
            };

            self.conn.execute(
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
                    idx as i64 + 1,  // orde starts at 1
                    initial,
                    hash,
                ],
            )?;
        }

        Ok(item_uuid)
    }

    /// Add a new field to an existing item
    pub fn add_field(&self, item_uuid: &str, field_type: &str, value: &str, sensitive: bool) -> Result<()> {
        // Get the item to get its encryption key
        let item = self.find_item_by_uuid(item_uuid)?
            .ok_or_else(|| VaultError::DecryptionError("Item not found".into()))?;

        let key = item.key.as_ref()
            .ok_or_else(|| VaultError::DecryptionError("Item has no encryption key".into()))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Find next available item_field_uid
        let max_uid: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(item_field_uid), 9) FROM itemfield WHERE item_uuid = ?",
            rusqlite::params![item_uuid],
            |row| row.get(0),
        )?;
        let new_uid = max_uid + 1;

        // Find next orde value
        let max_orde: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(orde), 0) FROM itemfield WHERE item_uuid = ? AND deleted = 0",
            rusqlite::params![item_uuid],
            |row| row.get(0),
        )?;
        let new_orde = max_orde + 1;

        // Encrypt if sensitive
        let field_value = if sensitive {
            encrypt_field(value, key, item_uuid)?
        } else {
            value.to_string()
        };

        // Compute hash (SHA1 of value)
        let hash = if !value.is_empty() {
            use sha1::{Sha1, Digest};
            let mut hasher = Sha1::new();
            hasher.update(value.as_bytes());
            hex::encode(hasher.finalize())
        } else {
            String::new()
        };

        // Initial is first 2 chars for sensitive fields
        let initial = if sensitive && !value.is_empty() {
            value.chars().take(2).collect::<String>()
        } else {
            String::new()
        };

        // Insert the field
        self.conn.execute(
            "INSERT INTO itemfield (item_uuid, item_field_uid, label, value, type, sensitive, deleted, historical, form_id, updated_at, value_updated_at, orde, wearable, history, initial, hash, strength, algo_version, expiry, excluded, pwned_check_time, extra)
             VALUES (?, ?, '', ?, ?, ?, 0, 1, '', ?, ?, ?, 0, '', ?, ?, -1, 1, 0, 0, 0, '')",
            rusqlite::params![
                item_uuid,
                new_uid,
                field_value,
                field_type,
                if sensitive { 1 } else { 0 },
                now,
                now,
                new_orde,
                initial,
                hash,
            ],
        )?;

        // Update item timestamps
        self.conn.execute(
            "UPDATE item SET field_updated_at = ?, updated_at = ? WHERE uuid = ?",
            rusqlite::params![now, now, item_uuid],
        )?;

        Ok(())
    }

    /// Remove a field from an item (soft-delete)
    pub fn remove_field(&self, item_uuid: &str, field_type: &str) -> Result<bool> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let rows_affected = self.conn.execute(
            "UPDATE itemfield SET deleted = 1, updated_at = ? WHERE item_uuid = ? AND type = ? AND deleted = 0",
            rusqlite::params![now, item_uuid, field_type],
        )?;

        if rows_affected > 0 {
            // Update item timestamps
            self.conn.execute(
                "UPDATE item SET field_updated_at = ?, updated_at = ? WHERE uuid = ?",
                rusqlite::params![now, now, item_uuid],
            )?;
        }

        Ok(rows_affected > 0)
    }

    /// Soft-delete an item
    pub fn delete_item(&self, item_uuid: &str) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        self.conn.execute(
            "UPDATE item SET deleted = 1, trashed = 1, updated_at = ? WHERE uuid = ?",
            rusqlite::params![now, item_uuid],
        )?;

        Ok(())
    }

    /// Find item by exact UUID
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
        let value = match &self.value {
            Some(v) if !v.is_empty() => v,
            _ => return Ok(String::new()),
        };

        if self.sensitive == 0 {
            return Ok(String::from_utf8_lossy(value).to_string());
        }

        if item_key.len() < 44 {
            return Err(VaultError::DecryptionError(format!(
                "Invalid item key length: {}",
                item_key.len()
            )));
        }

        // Value might be hex-encoded (stored as text), decode if needed
        let ciphertext = if value.iter().all(|b| b.is_ascii_hexdigit()) {
            // It's hex-encoded, decode it
            let hex_str = String::from_utf8_lossy(value);
            hex::decode(hex_str.as_ref())
                .map_err(|e| VaultError::DecryptionError(format!("Hex decode error: {}", e)))?
        } else {
            value.clone()
        };

        if ciphertext.len() < 16 {
            return Err(VaultError::DecryptionError(
                "Encrypted value too short".into(),
            ));
        }

        let aes_key = &item_key[0..32];
        let nonce_bytes = &item_key[32..44];

        let cipher = Aes256Gcm::new_from_slice(aes_key)
            .map_err(|e| VaultError::DecryptionError(e.to_string()))?;
        let nonce = Nonce::from_slice(nonce_bytes);

        // AAD is UUID without dashes, hex-decoded to bytes
        let aad_hex = uuid.replace("-", "");
        let aad = hex::decode(&aad_hex)
            .map_err(|e| VaultError::DecryptionError(format!("AAD hex decode: {}", e)))?;

        let plaintext = cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|e| VaultError::DecryptionError(e.to_string()))?;

        Ok(String::from_utf8_lossy(&plaintext).to_string())
    }

    pub fn display_label(&self) -> &str {
        if self.label.is_empty() {
            &self.field_type
        } else {
            &self.label
        }
    }
}

/// Encrypt a field value using AES-GCM
fn encrypt_field(plaintext: &str, item_key: &[u8], uuid: &str) -> Result<String> {
    use aes_gcm::aead::Aead;

    if item_key.len() < 44 {
        return Err(VaultError::DecryptionError(format!(
            "Invalid item key length: {}",
            item_key.len()
        )));
    }

    let aes_key = &item_key[0..32];
    let nonce_bytes = &item_key[32..44];

    let cipher = Aes256Gcm::new_from_slice(aes_key)
        .map_err(|e| VaultError::DecryptionError(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    // AAD is UUID without dashes, hex-decoded to bytes
    let aad_hex = uuid.replace("-", "");
    let aad = hex::decode(&aad_hex)
        .map_err(|e| VaultError::DecryptionError(format!("AAD hex decode: {}", e)))?;

    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|e| VaultError::DecryptionError(e.to_string()))?;

    // Return hex-encoded ciphertext (includes auth tag)
    Ok(hex::encode(ciphertext))
}

fn derive_key(password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut key = vec![0u8; 64];
    pbkdf2_hmac::<Sha512>(password.as_bytes(), salt, iterations, &mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let key = derive_key("test", b"0123456789abcdef", 1000);
        assert_eq!(key.len(), 64);
    }
}
