**RunnerAC (Console-based Game with Anti-Cheat)**

### **Compilation Command**

```bat
cl /std:c++17 /O2 /EHsc /DUNICODE /D_UNICODE RunnerAC.cpp /Fe:RunnerAC.exe /link Bcrypt.lib
```

### **Steps**

1. Open a **Developer Command Prompt for Visual Studio**.
2. Navigate to the project folder:

   ```bat
   cd C:\Users\<YourName>\Desktop\ProjectRunner
   ```
3. Run the compilation command above.
4. The output will be `RunnerAC.exe` in the same directory.
5. No extra runtime dependencies are required beyond the executable.

---
**AntiCheatSDL (SDL2-based Visual Game with Anti-Cheat)**

### **Compilation Command**

```bat
cl /std:c++17 /O2 /EHsc /DUNICODE /D_UNICODE /D SDL_MAIN_HANDLED ^
  sdl_anticheat.cpp /Fe:AntiCheatSDL.exe ^
  /I"%VCPKG_ROOT%\installed\x64-windows\include" ^
  /I"%VCPKG_ROOT%\installed\x64-windows\include\SDL2" ^
  /link /LIBPATH:"%VCPKG_ROOT%\installed\x64-windows\lib" ^
  SDL2.lib SDL2_ttf.lib Bcrypt.lib
```

### **Steps**

1. Make sure **vcpkg** is installed and integrated with Visual Studio.
2. Install dependencies via vcpkg if not already done:

   ```bat
   vcpkg install sdl2 sdl2-ttf
   ```
3. Open a **Developer Command Prompt for Visual Studio**.
4. Navigate to the project folder:

   ```bat
   cd C:\Users\<YourName>\Desktop\ProjectSDL
   ```
5. Run the compilation command above.
6. After successful compilation, `AntiCheatSDL.exe` will be generated.
7. Copy required runtime DLLs from vcpkg into the executable folder:

   * `SDL2.dll`
   * `SDL2_ttf.dll`
     (found in `%VCPKG_ROOT%\installed\x64-windows\bin`)
8. Run the game:

   ```bat
   AntiCheatSDL.exe
   ```
