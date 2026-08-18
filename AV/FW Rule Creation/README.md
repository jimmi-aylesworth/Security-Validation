# Readme

After reviewing and making any necessary changes, these can be compiled via:

```bash
x86_64-w64-mingw32-g++ {{FILEIN}}.cpp -static-libstdc++ -static-libgcc -lole32 -loleaut32 -o {{FILEOUT}}.exe
```