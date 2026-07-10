# Ransomware Simulation

Ransomware activity testing written in Rust.

# Instructions

1. Install Rust
2. Create two new projects; 1 for encryptor, 1 for decryptor
   - https://rust-lang.org/learn/get-started/
3. Place code in appropriate places
  ```text
  C:\PROJECT
  ├───src
  │   ├───main.rs
  └───Cargo.toml          
  ```
4. Build
  ```shell
  $ cargo clean
  $ cargo test
  $ cargo build --target x86_64-pc-windows-gnu --release        # target req. when compiled on Linux
  $ cargo clippy --allow-dirty --release --fix -- -D warnings   # optional
  ```
5. Pack (Optional)
   - Grab an updated copy of UPX - https://github.com/upx/upx/releases
   - unzip, read instructions, and pack away.

  ```cmd
  PS C:\> .\upx.exe -9 -f .\RanSim.exe
                         Ultimate Packer for eXecutables
                            Copyright (C) 1996 - 2026
  UPX 5.1.1       Markus Oberhumer, Laszlo Molnar & John Reiser    Mar 5th 2026
  
          File size         Ratio      Format      Name
     --------------------   ------   -----------   -----------
      448512 ->    194560   43.38%    win64/pe     RanSim.exe                                                                                                                                                                                                                                                                Packed 1 file.
  PS C:\> .\upx.exe -9 -f .\Ransim-D.exe
                         Ultimate Packer for eXecutables
                            Copyright (C) 1996 - 2026
  UPX 5.1.1       Markus Oberhumer, Laszlo Molnar & John Reiser    Mar 5th 2026
  
          File size         Ratio      Format      Name
     --------------------   ------   -----------   -----------
      372736 ->    160256   42.99%    win64/pe     Ransim-D.exe                                                                                                                                                                                                                                                              Packed 1 file.
  ```

---

# Creating Private and Public Keys

```shell
$ openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private_key.pem
$ openssl pkey -in private_key.pem -pubout -out public_key.pem
```

--- 

# Creating Mutex

```shell
$ ./mutex_handler.sh -e "Global\\RanSim_Mutex_95782\0"
```

--- 

# For linux - install mingw

```bash
pacman -S mingw-w64-x86_64-gcc        # Pacman
apt install -y mingw-w64-x86_64-gcc   # Aptitude
```

