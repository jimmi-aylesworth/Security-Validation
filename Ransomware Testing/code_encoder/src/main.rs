//! XOR command-obfuscation harness — ANNOTATED reference copy.
//!
//! This file is functionally identical to the production `main.rs`; only
//! comments have been added. Do NOT ship this copy — keep it beside the repo
//! as the "why does this work the way it does" reference. Behaviour-changing
//! fixes are described in comments but NOT applied here, so this annotated
//! copy stays a 1:1 mirror of the running binary. Apply fixes in the real
//! source, see README.md "Known bugs & fixes".

use std::process::Command;

// ---------------------------------------------------------------------------
// XOR key.
//
// Single byte, applied to every byte of the command string. 0x55 is
// 0b0101_0101 (ASCII 'U'). Any non-zero value works; changing it only changes
// the encoded byte array, not the strength. See README "Security properties":
// a single-byte XOR is trivially reversible and offers ~no resistance to a
// real analyst or AV engine. It only defeats a naive `strings` dump.
// ---------------------------------------------------------------------------
const XOR_KEY: u8 = 0x55;

/// XOR-encode a string into a byte vector.
///
/// Iterates the UTF-8 *bytes* of `input` (not chars) and XORs each with `key`.
/// For ASCII commands (all we ever use) this is exact and reversible. For
/// non-ASCII input see the round-trip caveat on `xor_decode`.
fn xor_encode(input: &str, key: u8) -> Vec<u8> {
    input.bytes().map(|b| b ^ key).collect()
}

/// XOR-decode a byte slice back into a String.
///
/// XORs each byte with `key` and casts the result to `char`.
///
/// CAVEAT (ASCII-only round-trip): `as char` treats each decoded byte as a
/// Unicode scalar value in U+0000..=U+00FF and then String stores it as UTF-8.
/// For any decoded byte >= 0x80 that means the byte is re-encoded as a 2-byte
/// UTF-8 sequence, so `decode(encode(s)) != s` for non-ASCII `s`. Commands here
/// are pure ASCII, so this never bites in practice — but a maintainer who feeds
/// it UTF-8 will get corruption. Fix in README if that ever matters.
fn xor_decode(input: &[u8], key: u8) -> String {
    input.iter().map(|b| (b ^ key) as char).collect()
}

fn main() {
    // -----------------------------------------------------------------------
    // STEP 1 — the command to hide, in cleartext.
    //
    // WARNING: as long as this stays a string *literal*, the cleartext lives
    // in the binary's .rodata and `strings` will find it. The obfuscation only
    // takes effect once you complete STEP 3 (replace this + the encode call
    // with a hardcoded byte array). As written below, nothing is hidden yet.
    // -----------------------------------------------------------------------
    let plaintext_command = "ifconfig /all";

    // -----------------------------------------------------------------------
    // STEP 2 — one-time generation of the encoded bytes.
    //
    // Run the program once and copy the "Encoded : [...]" line from stdout.
    // -----------------------------------------------------------------------
    let encoded = xor_encode(plaintext_command, XOR_KEY);

    // Dev/demonstration output. NOTE: these three prints leak the cleartext at
    // runtime, which defeats the whole point in a real deployment. Strip them
    // (and STEP 1's literal) before using this for anything but a demo.
    println!("Original : {}", plaintext_command);
    println!("Encoded  : {:?}", encoded);

    // -----------------------------------------------------------------------
    // STEP 3 — bake the bytes in.
    //
    // In a hardened build you replace the line below with the literal array you
    // copied in STEP 2, e.g.:
    //     let encoded_command: Vec<u8> = vec![0x3c, 0x33, 0x0a, ...];
    // and delete STEP 1 + STEP 2. As shipped it just reuses `encoded`, so the
    // cleartext path is still fully present.
    // -----------------------------------------------------------------------
    let encoded_command = encoded;

    // -----------------------------------------------------------------------
    // STEP 4 — decode at runtime, just before use.
    // -----------------------------------------------------------------------
    let decoded_command = xor_decode(&encoded_command, XOR_KEY);

    println!("Decoded  : {}", decoded_command);

    // -----------------------------------------------------------------------
    // STEP 5 — execute.
    //
    // BUGS (documented, not fixed here — see README "Known bugs & fixes"):
    //   1. `decoded_command` already contains " /all", and a second "/all" arg
    //      is appended, yielding:  cmd /c "ifconfig /all" /all
    //   2. `ifconfig` is a Linux tool. The Windows equivalent is `ipconfig`.
    //      As written this fails on Windows with "not recognized".
    //   3. Passing the whole "verb + args" string as ONE argv element to
    //      `cmd /c` is fragile — cmd's quote handling for a single quoted token
    //      is quirky. Prefer either a single joined string or splitting the
    //      decoded command into verb + args yourself.
    //   4. Requires a Windows `cmd` at runtime (Wine if you cross-compiled via
    //      MinGW on Linux).
    // -----------------------------------------------------------------------
    let output = Command::new("cmd")
        .args(["/c", &decoded_command, "/all"])
        .output()
        .expect("Failed to execute command");

    // Best-effort UTF-8 of whatever the child wrote to stdout.
    // NOTE: stderr is captured by .output() but never printed — a failing
    // command will look like it produced no output. Consider also printing
    // String::from_utf8_lossy(&output.stderr) when debugging.
    println!(
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
