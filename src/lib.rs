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

        let aad = uuid.replace("-", "");

        let plaintext = cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: &ciphertext,
                    aad: aad.as_bytes(),
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
