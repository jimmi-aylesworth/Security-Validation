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
// Now a 4-byte *repeating* key applied cyclically: input byte i is XORed with
// X_KEY[i % X_KEY.len()]. 0xde 0xad 0xbe 0xef is just a recognizable filler
// pattern; any non-empty byte sequence works, and the specific bytes only
// change the encoded output, not the strength.
//
// Security properties (unchanged in spirit — see README "Security properties"):
// a repeating-key XOR is still trivially reversible. It's marginally more work
// than the old single-byte key — an analyst recovers 4 key bytes instead of 1 —
// but with known plaintext (and these commands are guessable) the key falls
// straight out, and given enough ciphertext a short repeating key is recoverable
// by Kasiski/frequency analysis anyway. As before, this only defeats a naive
// `strings` dump; it is NOT cryptography and offers ~no resistance to a real
// analyst or AV engine.
//
// (Renamed XOR_KEY -> X_KEY and changed the type from `u8` to `&[u8]`; every
// use site below was updated to match.)
// ---------------------------------------------------------------------------
const X_KEY: &[u8] = &[
    0xde, 0xad, 0xbe, 0xef,
];

/// XOR-encode a string into a byte vector using a repeating key.
///
/// Iterates the UTF-8 *bytes* of `input` (not chars) and XORs each with the
/// corresponding key byte. `key.iter().cycle()` repeats the key indefinitely,
/// so byte i uses `key[i % key.len()]`. For ASCII commands (all we ever use)
/// this is exact and reversible. For non-ASCII input see the round-trip caveat
/// on `xor_decode`.
///
/// EMPTY-KEY CAVEAT: `cycle()` over an empty slice yields nothing, so `zip`
/// produces an empty Vec rather than panicking — a silent no-op that encodes to
/// zero bytes. X_KEY is always 4 bytes so this can't happen here, but a
/// maintainer who wires in a runtime-supplied key should guard `key.is_empty()`.
fn xor_encode(input: &str, key: &[u8]) -> Vec<u8> {
    input
        .bytes()
        .zip(key.iter().cycle())
        .map(|(b, &k)| b ^ k)
        .collect()
}

/// XOR-decode a byte slice back into a String using a repeating key.
///
/// Mirrors `xor_encode`: XORs each byte with the cycled key byte and casts the
/// result to `char`.
///
/// CAVEAT (ASCII-only round-trip): unchanged from the single-byte version.
/// `as char` treats each decoded byte as a Unicode scalar value in
/// U+0000..=U+00FF and then String stores it as UTF-8. For any decoded byte
/// >= 0x80 that means the byte is re-encoded as a 2-byte UTF-8 sequence, so
/// `decode(encode(s)) != s` for non-ASCII `s`. Commands here are pure ASCII, so
/// this never bites in practice — but a maintainer who feeds it UTF-8 will get
/// corruption. Fix in README if that ever matters.
fn xor_decode(input: &[u8], key: &[u8]) -> String {
    input
        .iter()
        .zip(key.iter().cycle())
        .map(|(&b, &k)| (b ^ k) as char)
        .collect()
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
    let plaintext_command = "ipconfig";

    // -----------------------------------------------------------------------
    // STEP 2 — one-time generation of the encoded bytes.
    //
    // Run the program once and copy the "Encoded : [...]" line from stdout.
    // For "ifconfig /all" under the current X_KEY the encoded bytes are:
    //   [0xb7, 0xcb, 0xdd, 0x80, 0xb0, 0xcb, 0xd7, 0x88, 0xfe, 0x82, 0xdf,
    //    0x83, 0xb2]
    // (Re-generate whenever you change either the command or X_KEY.)
    // -----------------------------------------------------------------------
    let encoded = xor_encode(plaintext_command, X_KEY);

    // Dev/demonstration output. NOTE: these prints leak the cleartext at
    // runtime, which defeats the whole point in a real deployment. Strip them
    // (and STEP 1's literal) before using this for anything but a demo.
    println!("Original : {}", plaintext_command);
    println!("Encoded  : {:?}", encoded);

    // -----------------------------------------------------------------------
    // STEP 3 — bake the bytes in.
    //
    // In a hardened build you replace the line below with the literal array you
    // copied in STEP 2, e.g.:
    //     let encoded_command: Vec<u8> = vec![0xb7, 0xcb, 0xdd, /* ... */];
    // and delete STEP 1 + STEP 2. As shipped it just reuses `encoded`, so the
    // cleartext path is still fully present.
    // -----------------------------------------------------------------------
    let encoded_command = encoded;

    // -----------------------------------------------------------------------
    // STEP 4 — decode at runtime, just before use.
    // -----------------------------------------------------------------------
    let decoded_command = xor_decode(&encoded_command, X_KEY);

    println!("Decoded  : {}", decoded_command);

    // -----------------------------------------------------------------------
    // STEP 5 — execute.
    //
    // BUGS (documented, not fixed here — see README "Known bugs & fixes"):
    //   1. Passing the whole "verb + args" string as ONE argv element to
    //      `cmd /c` is fragile — cmd's quote handling for a single quoted token
    //      is quirky. Prefer either a single joined string or splitting the
    //      decoded command into verb + args yourself.
    //   2. Requires a Windows `cmd` at runtime (Wine if you cross-compiled via
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
