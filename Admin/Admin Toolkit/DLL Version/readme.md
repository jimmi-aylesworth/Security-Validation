A rundll32-loadable, fully self-contained COM/ADSI local-account administration DLL.

Built for exercising Windows Security-log detection rules (account creation/deletion/modification based on event IDs).

For LAB use ONLY.

Compile:

```bash
x86_64-w64-mingw32-g++ -std=c++17 -Wall -shared -static-libstdc++ -static-libgcc -static \
   admin_toolkit_dll.cpp admin_toolkit_dll.def -o admin_toolkit.dll \
   -lactiveds -ladsiid -lole32 -loleaut32
```
