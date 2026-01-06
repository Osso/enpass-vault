use enpass_vault::{Vault, VaultError};
use std::path::PathBuf;

fn test_vault_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test_vault")
}

const TEST_PASSWORD: &str = "test123";

#[test]
fn test_open_vault_correct_password() {
    let vault = Vault::open(test_vault_path(), TEST_PASSWORD);
    assert!(vault.is_ok(), "Should open vault with correct password");
}

#[test]
fn test_open_vault_wrong_password() {
    let result = Vault::open(test_vault_path(), "wrong_password");
    assert!(matches!(result, Err(VaultError::WrongPassword)));
}

#[test]
fn test_list_items() {
    let vault = Vault::open(test_vault_path(), TEST_PASSWORD).unwrap();
    let items = vault.list_items(None).unwrap();

    // At least 4 items from fixtures (tests may create additional temporary items)
    assert!(items.len() >= 4, "Should have at least 4 test items, got {}", items.len());

    let titles: Vec<&str> = items.iter().map(|i| i.title.as_str()).collect();
    assert!(titles.contains(&"Test Login"));
    assert!(titles.contains(&"Another Login"));
    assert!(titles.contains(&"Credit Card"));
    assert!(titles.contains(&"Secure Note"));
}

#[test]
fn test_list_items_by_category() {
    let vault = Vault::open(test_vault_path(), TEST_PASSWORD).unwrap();

    let logins = vault.list_items(Some("login")).unwrap();
    assert!(logins.len() >= 2, "Should have at least 2 login items");

    let cards = vault.list_items(Some("creditcard")).unwrap();
    assert!(cards.len() >= 1, "Should have at least 1 credit card item");

    let notes = vault.list_items(Some("note")).unwrap();
    assert!(notes.len() >= 1, "Should have at least 1 note item");
}

#[test]
fn test_find_item() {
    let vault = Vault::open(test_vault_path(), TEST_PASSWORD).unwrap();

    let item = vault.find_item("Test Login").unwrap();
    assert!(item.is_some(), "Should find Test Login");
    let item = item.unwrap();
    assert_eq!(item.title, "Test Login");
    assert_eq!(item.category, "login");
    assert!(item.key.is_some(), "Item should have encryption key");
}

#[test]
fn test_find_item_partial_match() {
    let vault = Vault::open(test_vault_path(), TEST_PASSWORD).unwrap();

    let item = vault.find_item("Another").unwrap();
    assert!(item.is_some(), "Should find item with partial match");
    assert_eq!(item.unwrap().title, "Another Login");
}

#[test]
fn test_find_item_not_found() {
    let vault = Vault::open(test_vault_path(), TEST_PASSWORD).unwrap();

    let item = vault.find_item("Nonexistent Item").unwrap();
    assert!(item.is_none(), "Should return None for nonexistent item");
}

#[test]
fn test_get_fields() {
    let vault = Vault::open(test_vault_path(), TEST_PASSWORD).unwrap();

    let item = vault.find_item("Test Login").unwrap().unwrap();
    let fields = vault.get_fields(&item.uuid).unwrap();

    assert_eq!(fields.len(), 3, "Test Login should have 3 fields");

    let field_types: Vec<&str> = fields.iter().map(|f| f.field_type.as_str()).collect();
    assert!(field_types.contains(&"username"));
    assert!(field_types.contains(&"password"));
    assert!(field_types.contains(&"url"));
}

#[test]
fn test_decrypt_sensitive_field() {
    let vault = Vault::open(test_vault_path(), TEST_PASSWORD).unwrap();

    let item = vault.find_item("Test Login").unwrap().unwrap();
    let fields = vault.get_fields(&item.uuid).unwrap();
    let key = item.key.as_ref().unwrap();

    let password_field = fields.iter().find(|f| f.field_type == "password").unwrap();
    assert_eq!(password_field.sensitive, 1, "Password should be sensitive");

    let decrypted = password_field.decrypt(key, &item.uuid).unwrap();
    assert_eq!(decrypted, "secretpass123");
}

#[test]
fn test_decrypt_non_sensitive_field() {
    let vault = Vault::open(test_vault_path(), TEST_PASSWORD).unwrap();

    let item = vault.find_item("Test Login").unwrap().unwrap();
    let fields = vault.get_fields(&item.uuid).unwrap();
    let key = item.key.as_ref().unwrap();

    let username_field = fields.iter().find(|f| f.field_type == "username").unwrap();
    assert_eq!(username_field.sensitive, 0, "Username should not be sensitive");

    let decrypted = username_field.decrypt(key, &item.uuid).unwrap();
    assert_eq!(decrypted, "testuser");
}

#[test]
fn test_search() {
    let vault = Vault::open(test_vault_path(), TEST_PASSWORD).unwrap();

    // Search by title
    let results = vault.search("Login").unwrap();
    assert_eq!(results.len(), 2, "Should find 2 items with 'Login' in title");

    // Search by URL field value
    let results = vault.search("example.com").unwrap();
    assert!(!results.is_empty(), "Should find items with example.com in fields");
}

#[test]
fn test_get_categories() {
    let vault = Vault::open(test_vault_path(), TEST_PASSWORD).unwrap();

    let categories = vault.get_categories().unwrap();
    assert_eq!(categories.len(), 3, "Should have 3 categories");
    assert!(categories.contains(&"login".to_string()));
    assert!(categories.contains(&"creditcard".to_string()));
    assert!(categories.contains(&"note".to_string()));
}

#[test]
fn test_create_and_delete_item() {
    let vault = Vault::open(test_vault_path(), TEST_PASSWORD).unwrap();

    // Create new item
    let uuid = vault
        .create_item(
            "Temporary Item",
            "login",
            &[
                ("username", "tempuser", false),
                ("password", "temppass", true),
            ],
        )
        .unwrap();

    // Verify it exists
    let item = vault.find_item_by_uuid(&uuid).unwrap();
    assert!(item.is_some(), "Created item should exist");
    assert_eq!(item.unwrap().title, "Temporary Item");

    // Delete it
    vault.delete_item(&uuid).unwrap();

    // Verify it's trashed (find_item excludes trashed)
    let item = vault.find_item("Temporary Item").unwrap();
    assert!(item.is_none(), "Deleted item should not be found");
}

#[test]
fn test_update_field() {
    let vault = Vault::open(test_vault_path(), TEST_PASSWORD).unwrap();

    // Create a test item
    let uuid = vault
        .create_item(
            "Update Test Item",
            "login",
            &[("password", "original", true)],
        )
        .unwrap();

    // Update the password
    vault.update_field(&uuid, "password", "updated_password").unwrap();

    // Verify the update
    let item = vault.find_item_by_uuid(&uuid).unwrap().unwrap();
    let fields = vault.get_fields(&uuid).unwrap();
    let key = item.key.as_ref().unwrap();

    let password_field = fields.iter().find(|f| f.field_type == "password").unwrap();
    let decrypted = password_field.decrypt(key, &uuid).unwrap();
    assert_eq!(decrypted, "updated_password");

    // Clean up
    vault.delete_item(&uuid).unwrap();
}

#[test]
fn test_add_field() {
    let vault = Vault::open(test_vault_path(), TEST_PASSWORD).unwrap();

    // Create a test item with one field
    let uuid = vault
        .create_item("Add Field Test", "login", &[("username", "user", false)])
        .unwrap();

    // Add a new field
    vault.add_field(&uuid, "password", "newpass", true).unwrap();

    // Verify the field was added
    let item = vault.find_item_by_uuid(&uuid).unwrap().unwrap();
    let fields = vault.get_fields(&uuid).unwrap();
    assert_eq!(fields.len(), 2, "Should have 2 fields now");

    let password_field = fields.iter().find(|f| f.field_type == "password").unwrap();
    let decrypted = password_field.decrypt(item.key.as_ref().unwrap(), &uuid).unwrap();
    assert_eq!(decrypted, "newpass");

    // Clean up
    vault.delete_item(&uuid).unwrap();
}

#[test]
fn test_remove_field() {
    let vault = Vault::open(test_vault_path(), TEST_PASSWORD).unwrap();

    // Create a test item with two fields
    let uuid = vault
        .create_item(
            "Remove Field Test",
            "login",
            &[
                ("username", "user", false),
                ("password", "pass", true),
            ],
        )
        .unwrap();

    // Remove the password field
    let removed = vault.remove_field(&uuid, "password").unwrap();
    assert!(removed, "Should return true when field is removed");

    // Verify the field was removed
    let fields = vault.get_fields(&uuid).unwrap();
    assert_eq!(fields.len(), 1, "Should have 1 field now");
    assert_eq!(fields[0].field_type, "username");

    // Try to remove non-existent field
    let removed = vault.remove_field(&uuid, "nonexistent").unwrap();
    assert!(!removed, "Should return false for non-existent field");

    // Clean up
    vault.delete_item(&uuid).unwrap();
}

#[test]
fn test_display_label() {
    use enpass_vault::ItemField;

    let field_with_label = ItemField {
        label: "Custom Label".to_string(),
        value: None,
        field_type: "text".to_string(),
        sensitive: 0,
    };
    assert_eq!(field_with_label.display_label(), "Custom Label");

    let field_without_label = ItemField {
        label: String::new(),
        value: None,
        field_type: "password".to_string(),
        sensitive: 1,
    };
    assert_eq!(field_without_label.display_label(), "password");
}
