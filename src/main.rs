use rand::random;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32};

fn server(e_client_value: FheUint32) -> FheUint32 {
    println!("SERVER: Received value from client");

    let server_hashes = vec![123456u32, 623453u32, 423458u32];
    println!(
        "SERVER: Image that the following is the database: {:?}",
        server_hashes
    );

    let server_r: u32 = random();
    println!(
        "SERVER: And a secret value that only the server knows: {}",
        server_r
    );

    let e_server_r = FheUint32::encrypt_trivial(server_r);
    let e_server_hashes = server_hashes
        .iter()
        .map(|&server_hash| FheUint32::encrypt_trivial(server_hash));

    print!("SERVER: Subtracting each database entry from clients value and multiplying");
    let test_equal = e_server_hashes
        .map(|e_server_hash| &e_client_value - &e_server_hash)
        .fold(FheUint32::encrypt_trivial(1), |acc, e| &acc * &e);

    // Note: We multiply instead of taking the power as no exponentiation function
    // is present and iteratively adding would be too computationally expensive
    println!("SERVER: Returning the test value multied by r");
    return &test_equal * &e_server_r;
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Basic configuration to use homomorphic integers
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    // Key generation, client key is secret!
    let (client_key, server_key) = generate_keys(config);

    // Publish server key
    set_server_key(server_key);

    let client_hash = 123456u32;
    println!(
        "CLIENT: Wants to know is server has {} in its database",
        client_hash
    );

    // Hash is encrypted using the (private) client_key and sent to the server
    let e_client_hash = FheUint32::try_encrypt(client_hash, &client_key)?;
    println!("CLIENT: Encrypts the value and sends it to the server");

    //  Let the server to its work
    let server_response = server(e_client_hash);

    // Decrypting on the client side:
    let clear_res: u32 = server_response.decrypt(&client_key);
    println!("CLIENT: Decrypted server response is {}", clear_res);

    if clear_res == 0 {
        println!("CLIENT: value is in the database 👏");
    } else {
        println!("CLIENT: value is NOT in the database 👎");
    }

    println!("");
    println!("Test another value");

    let client_hash = 324455u32;
    println!(
        "CLIENT: Wants to know is server has {} in its database",
        client_hash
    );

    let e_client_hash = FheUint32::try_encrypt(client_hash, &client_key)?;
    println!("CLIENT: Encrypts the value and sends it to the server");

    let server_response = server(e_client_hash);

    let clear_res: u32 = server_response.decrypt(&client_key);
    println!("CLIENT: Decrypted server response is {}", clear_res);

    if clear_res == 0 {
        println!("CLIENT: value is in the database 👏");
    } else {
        println!("CLIENT: value is NOT in the database 👎");
    }

    Ok(())
}
