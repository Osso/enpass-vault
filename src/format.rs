use rusqlite::Connection;

use crate::{Result, VaultError};

const ITEM_COLUMNS: &[&str] = &[
    "uuid",
    "created_at",
    "meta_updated_at",
    "field_updated_at",
    "title",
    "subtitle",
    "note",
    "icon",
    "category",
    "template",
    "key",
    "updated_at",
    "last_used",
    "trashed",
    "deleted",
    "favorite",
    "auto_submit",
];

const ITEMFIELD_COLUMNS: &[&str] = &[
    "item_uuid",
    "item_field_uid",
    "label",
    "value",
    "type",
    "sensitive",
    "deleted",
    "historical",
    "form_id",
    "updated_at",
    "value_updated_at",
    "orde",
    "wearable",
    "history",
    "initial",
    "hash",
    "strength",
    "algo_version",
    "expiry",
    "excluded",
    "pwned_check_time",
    "extra",
];

pub(crate) fn ensure_supported_write_schema(conn: &Connection) -> Result<()> {
    require_columns(conn, "item", ITEM_COLUMNS)?;
    require_columns(conn, "itemfield", ITEMFIELD_COLUMNS)
}

fn require_columns(conn: &Connection, table: &str, required_columns: &[&str]) -> Result<()> {
    let actual_columns = table_columns(conn, table)?;
    let missing_columns = missing_columns(required_columns, &actual_columns);

    if missing_columns.is_empty() {
        return Ok(());
    }

    Err(VaultError::UnsupportedVaultFormat(format!(
        "{table} is missing required columns: {}",
        missing_columns.join(", ")
    )))
}

fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = stmt
        .query([])?
        .mapped(|row| row.get(1))
        .collect::<std::result::Result<Vec<String>, _>>()?;

    if columns.is_empty() {
        return Err(VaultError::UnsupportedVaultFormat(format!(
            "missing table: {table}"
        )));
    }

    Ok(columns)
}

fn missing_columns<'a>(required_columns: &'a [&str], actual_columns: &[String]) -> Vec<&'a str> {
    required_columns
        .iter()
        .copied()
        .filter(|required| !actual_columns.iter().any(|actual| actual == required))
        .collect()
}
