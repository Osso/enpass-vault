//! Add test items to vault
//! Run with: cargo run --example add_test_items

use enpass_vault::Vault;

fn main() {
    let vault_path = "/home/osso/Documents/Enpass/Vaults/87d16630-baa2-4ac3-a591-102d0d5e43b4";
    let password = "none";

    let vault = Vault::open(vault_path, password).expect("Failed to open vault");

    for i in 1..=10 {
        let title = format!("Test Item {:02}", i);
        let fields = [
            ("username", &format!("user{}", i) as &str, false),
            ("password", &format!("pass{}", i) as &str, true),
            (
                "url",
                &format!("https://test{}.example.com", i) as &str,
                false,
            ),
        ];

        match vault.create_item(&title, "login", &fields) {
            Ok(uuid) => println!("Created: {} ({})", title, uuid),
            Err(e) => eprintln!("Failed to create {}: {}", title, e),
        }
    }

    println!("Done!");
}
