use super::*;

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
