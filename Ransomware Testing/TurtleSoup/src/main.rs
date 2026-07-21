use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use rsa::traits::PublicKeyParts;
use rsa::pkcs8::DecodePrivateKey; 
use walkdir::WalkDir;
use std::fs::{File};
use std::io::{Read, Write};

// Private key matching Public key used to encrypt
const RSA_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
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
h1Rmci6bEr1ohuWx0R/LAGSRN7aH32w=
-----END PRIVATE KEY-----"#;

struct DecryptionEngine {
    priv_key: RsaPrivateKey,
}

impl DecryptionEngine {
    fn new() -> Self {
        let priv_key = RsaPrivateKey::from_pkcs8_pem(RSA_PRIVATE_KEY_PEM)
            .expect("Failed to load RSA Private Key.");
        Self { priv_key }
    }

    fn decrypt_file(&self, path: &std::path::PathBuf) -> std::io::Result<()> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        // Separate the data
        // RSA 2048-bit keys produce 256 bytes of encrypted data
        // RSA 4096-bit keys produce 512 bytes of encrypted data
        // Make sure to set correctly or you won't decrypt!
        // update to use `self.priv_key.size()` and don't worry about it ;)
        //let rsa_key_len = 512; 
        let rsa_key_len = self.priv_key.size();
        let nonce_len = 12;
        
        if buffer.len() < (rsa_key_len + nonce_len) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "File too short"));
        }

        let split_point_key = buffer.len() - rsa_key_len;
        let split_point_nonce = split_point_key - nonce_len;

        let ciphertext = &buffer[..split_point_nonce];
        let nonce_bytes = &buffer[split_point_nonce..split_point_key];
        let encrypted_symmetric_key = &buffer[split_point_key..];

        // Decrypt the symmetric key using RSA Private key
        let symmetric_key_bytes = self.priv_key
            .decrypt(Pkcs1v15Encrypt, encrypted_symmetric_key)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // Decrypt the file content using AES-GCM
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&symmetric_key_bytes));
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // Restore original file extension
        let original_path = path.with_extension("");
        
        let mut out_file = File::create(&original_path)?;
        out_file.write_all(&plaintext)?;

        // Remove encrypted file
        std::fs::remove_file(path)?;
        
        Ok(())
    }
}

fn main() {
    let engine = DecryptionEngine::new();
    let root_dir = "C:\\Temp";

    println!("[*] Starting The Soup...");

    let files: Vec<_> = WalkDir::new(root_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("hare"))
        .collect();

    for entry in files {
        let path = entry.path().to_path_buf();
        match engine.decrypt_file(&path) {
            Ok(_) => println!("[+] Added: {:?}", path),
            Err(e) => eprintln!("[-] Bad ingredient {:?}: {}", path, e),
        }
    }

    println!("[+] Turtle Soup Complete.");
}
