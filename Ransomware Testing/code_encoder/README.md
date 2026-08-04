# XOR Command Harness — Maintainer Guide

> Documentation for the single-file Rust utility that XOR-obfuscates a
> command string, decodes it at runtime, and executes it via `cmd`.

---

## 1. What this actually is

A **single-byte XOR string-obfuscation harness**. It:

1. Holds a command as cleartext,
2. XOR-encodes it to a byte array (so the string doesn't sit in plain view),
3. XOR-decodes it back at runtime, and
4. runs it through the Windows `cmd` interpreter.

The bundled command (`ifconfig /all`) is a benign network-config lookup — it's a
placeholder demonstrating the technique, not the intended production payload.

**Be precise about what it does and doesn't do.** The description "keep prying
eyes from inspecting the code unless approved" is loose shorthand. Mechanically
there is **no access control and no approval step** here. What actually happens
is *string obfuscation*: the goal is to stop a command string from showing up in
a naive `strings` dump or a quick disassembly. That's a real but shallow
protection (see §5). If you were told this "gates" who can read the code, that's
not what the code does — it just makes one string non-obvious.

---

## 2. Files

| File                 | Purpose                                                        |
|----------------------|---------------------------------------------------------------|
| `main.rs`            | The production single-file program.                           |
| `main.annotated.rs` | 1:1 mirror of `main.rs` with heavy inline comments. Reference only — never build/ship it. |
| `README.md`          | This document.                                                |

---

## 3. How it works

### 3.1 The key
```rust
const XOR_KEY: u8 = 0x55;
```
One byte (`0b0101_0101`, ASCII `'U'`) XORed against every byte of the command.
Any non-zero value works; changing it only changes the encoded bytes, never the
strength.

### 3.2 `xor_encode(input: &str, key: u8) -> Vec<u8>`
Walks the UTF-8 **bytes** of `input` and XORs each with `key`. Used once, at
"authoring" time, to produce the byte array you paste into the binary.

### 3.3 `xor_decode(input: &[u8], key: u8) -> String`
Reverses the above and casts each byte to `char`. XOR is symmetric, so decode is
the same operation as encode.

> **ASCII-only caveat.** Decode does `(byte ^ key) as char`, which maps a byte
> to code points U+0000..=U+00FF and re-stores them as UTF-8. Any decoded byte
> ≥ 0x80 becomes a 2-byte UTF-8 sequence, so `decode(encode(s)) != s` for
> non-ASCII `s`. All commands here are ASCII, so this is harmless today — but
> don't feed it Unicode without fixing this first.

### 3.4 `main` — the five-step flow
The inline comments label the flow STEP 1–5:

1. **STEP 1** — cleartext command literal.
2. **STEP 2** — encode once, print the byte array to stdout.
3. **STEP 3** — bake those bytes into the binary and delete the cleartext.
4. **STEP 4** — decode at runtime, right before use.
5. **STEP 5** — hand the decoded string to `cmd /c` and print stdout.

---

## 4. Intended workflow vs. as-shipped reality

The STEP comments describe a **two-phase authoring workflow**:

1. *Author phase* — put your command in STEP 1, run once, copy the
   `Encoded : [...]` line.
2. *Harden phase* — replace STEP 1's literal **and** STEP 2's `xor_encode`
   call with a hardcoded `let encoded_command: Vec<u8> = vec![...];`, then
   delete the cleartext and the debug `println`s.

**As currently written, phase 2 was never done.** The code still:
- keeps the cleartext string literal in the source (so it's in the compiled
  binary's `.rodata` — `strings` will find it), and
- prints `Original`, `Encoded`, and `Decoded` to stdout at runtime.

So in its current state the harness **obfuscates nothing** — it's still in demo
mode. To get any benefit you must complete the harden phase.

---

## 5. Security properties / limitations (read this)

- **Single-byte XOR is trivially reversible.** It is not encryption. Any analyst
  spots a repeating-key XOR immediately, and automated tooling (AV/EDR string
  deobfuscators, entropy + brute-force over 255 keys) breaks it in milliseconds.
  Treat it as "not visible to `strings`," nothing more.
- **The key is in the binary.** `XOR_KEY` ships with the program, so the decode
  routine and key travel together. There's no secret to protect the string with.
- **Cleartext leaks two ways in the current build:** the source literal (§4) and
  the runtime `println!`s. Both must go for the obfuscation to mean anything.
- **Scope is one string.** Function/symbol names, the `cmd` invocation, and
  program structure are all untouched and fully readable.

If you need real resistance, this is the wrong primitive — but it's fine as a
lab demonstration of the technique (which is what it's for).

---

## 6. Known bugs & fixes

These are in `main.rs`'s STEP 5 execution. The annotated copy documents them but
does **not** apply them; fix them in the real source.

1. **Redundant/duplicated argument.** `decoded_command` already ends in `/all`,
   and the code appends another `"/all"` arg → `cmd /c "ifconfig /all" /all`.
   Drop the trailing `"/all"`.
2. **Wrong verb for Windows.** `ifconfig` is Linux. The Windows equivalent is
   `ipconfig`. As written the child process errors with "not recognized."
3. **Fragile `cmd /c` argument shape.** Passing the entire "verb + args" as a
   single argv element to `cmd /c` relies on cmd's quirky single-token quote
   handling. Prefer one of:
   ```rust
   // (a) let cmd parse a single command line
   Command::new("cmd").args(["/c", &decoded_command]).output()

   // (b) split it yourself and skip cmd entirely
   let mut parts = decoded_command.split_whitespace();
   let verb = parts.next().unwrap();
   Command::new(verb).args(parts).output()
   ```
4. **stderr is dropped.** `.output()` captures stderr but the code only prints
   stdout, so failures look silent. Add:
   ```rust
   eprintln!("{}", String::from_utf8_lossy(&output.stderr));
   ```
5. **`.expect()` panics on spawn failure.** Fine for a lab tool; if you want
   graceful handling, match on the `Result` instead.

A corrected STEP 5 (Windows, `ipconfig /all`) looks like:
```rust
let output = Command::new("cmd")
    .args(["/c", &decoded_command])   // decoded_command == "ipconfig /all"
    .output()
    .expect("Failed to execute command");
println!("{}", String::from_utf8_lossy(&output.stdout));
eprintln!("{}", String::from_utf8_lossy(&output.stderr));
```
(with STEP 1 updated to `"ipconfig /all"` and re-encoded).

---

## 7. Build & run

Standard single-crate Rust:
```bash
cargo build --release
```

**Runtime requires a Windows `cmd`.** If you're on the usual Linux + MinGW
cross-compile setup:
```bash
cargo build --release --target x86_64-pc-windows-gnu
```
The resulting `.exe` needs Windows (or Wine) to actually run STEP 5, since it
shells out to `cmd`. Building on Linux succeeds; *running* it there will fail at
the `Command::new("cmd")` call unless Wine provides `cmd`.

---

## 8. How to change the command (the one routine maintenance task)

1. Put the new **ASCII** command in STEP 1's `plaintext_command`.
2. Run once, copy the `Encoded : [...]` array.
3. (If hardening) replace STEP 1 + STEP 2 with
   `let encoded_command: Vec<u8> = vec![/* pasted bytes */];`, delete the
   cleartext literal and the debug prints.
4. Confirm STEP 5's execution shape still matches the command's verb/args
   (see §6).

---

## 9. Observable behaviour / detection notes

Useful if this lives in the detection lab, since the whole value of a demo like
this is having something to write detections against:

- **Process lineage:** the harness binary spawns `cmd.exe /c <command>`. A
  parent process that isn't a shell/explorer spawning `cmd.exe` is the primary
  signal (Sysmon Event ID 1 / `ProcessCreate`, plus the process tree).
- **The obfuscation itself is invisible at the process layer** — by the time
  `cmd` runs, the command is already cleartext on the command line. So
  command-line logging (Sysmon EID 1 `CommandLine`, 4688 with cmdline auditing)
  fully defuses the string obfuscation. That's the teachable point: source-level
  string hiding does nothing against runtime command-line telemetry.
- **What XOR obfuscation *does* defeat** is static/string-based inspection of the
  binary at rest (`strings`, simple YARA string rules) — and only once §4's
  harden phase is actually done.
- If you extend this to avoid `cmd` (option 6(b), direct spawn), your detection
  pivots from "cmd child" to the specific verb's process-create event.

---

## 10. Quick glossary

- **XOR obfuscation** — reversibly scrambling bytes with `b ^ key`; symmetric, so
  the same routine encodes and decodes.
- **`.rodata`** — read-only data section of a compiled binary where string
  literals live; where `strings` finds cleartext.
- **`cmd /c`** — run the following command, then exit.
