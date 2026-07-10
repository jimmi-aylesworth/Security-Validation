# 🛡️ Operation RanSim
A High-Fidelity Ransomware Simulator for Security Validation

Ransim is a purpose-built ransomware simulator developed to test the efficacy of advanced ransomware protection products. Unlike basic simulators, this project implements real-world attacker methodologies to ensure that security telemetry and prevention logic are validated against actual threat actor behaviors.

## ⚠️ WARNING: USE WITH CAUTION
This is functional encryption software.

- **DO NOT** run this on a production machine.
- **DO NOT** run this on a system without a verified, offline backup.
- Run only in a controlled, isolated sandbox or Virtual Machine (VM).

### 🚀 Real-World Threat Model
To provide meaningful test results, Ransim avoids "simulated" behaviors (like XOR or simple renaming) and implements the following professional ransomware traits:

1. Hybrid Cryptography
    - Symmetric Encryption: Uses high-performance encryption for file payloads.
    - Asymmetric Wrapping: Implements a mock-up of the RSA-key wrapping process.
    - Unique Keys: Generates unique session keys to simulate real-world ransomware behavior.
2. System Interaction
    - Instance Control: Uses a Mutex ensuring only one instance of the program runs at a time.
    - Shadow Copy Deletion: Attempts deletion of Volume Shadow Copies (VSS) to prevent easy recovery.
    - Targeted Encryption: Filters files by extension to maximize impact and avoid crashing the OS.
3. Technical Stack
    - Language: Rust (memory safety and exec speed).
    - Concurrency: Multi-threaded for spead.
    - OS Target: Windows (via WinAPI).

### 🛠 Installation & Execution

**Prerequisites**
- Rust (Latest Stable)
- Windows OS (to test/run) <-- Build Target

**Build**
```
cargo build --release
```

**Run**
```
# WARNING: Run only in a dedicated VM/Sandbox environment
./target/release/Ransim.exe
```

### 📊 Validation Criteria
This tool is designed to test if a security product can detect:

- Mass File Encryption events.
- Unauthorized VSS (Volume Shadow Copy) deletions.
- Unusual Entropy increases in file headers.
- Rapid I/O patterns characteristic of ransomware.

---

_Disclaimer: This software is for educational and testing purposes only. Use responsibly._
