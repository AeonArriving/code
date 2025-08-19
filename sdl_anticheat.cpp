// sdl_anticheat.cpp - SDL2 visualization of AntiCheat Prototype (C++17, Windows)
// Features: Obfuscated values, SHA-256 code integrity, jittered watchdog,
// CE process scan, anti-freeze heuristic, heap relocation, CSV logging.
// UI: HP bar, Gold/Score text, detections & watchdog cost, hotkeys overlay.
//
// Build (MSVC + vcpkg):
//   cl /std:c++17 /O2 /EHsc /DUNICODE /D_UNICODE sdl_anticheat.cpp /Fe:AntiCheatSDL.exe ^
//     /I"%VCPKG_ROOT%\installed\x64-windows\include" ^
//     /link /LIBPATH:"%VCPKG_ROOT%\installed\x64-windows\lib" SDL2.lib SDL2main.lib SDL2_ttf.lib Bcrypt.lib
//
// If not using vcpkg, link SDL2.lib SDL2main.lib SDL2_ttf.lib and copy SDL2.dll/SDL2_ttf.dll next to exe.

#define SDL_MAIN_HANDLED
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <bcrypt.h>    // SHA-256
#pragma comment(lib, "Bcrypt.lib")

#include <SDL.h>
#include <SDL_ttf.h>
// #pragma comment(lib, "SDL2.lib")
// #pragma comment(lib, "SDL2main.lib")
// #pragma comment(lib, "SDL2_ttf.lib")

#include <cstdio>
#include <cstdint>
#include <thread>
#include <atomic>
#include <chrono>
#include <random>
#include <string>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <ctime>
#include <vector>
#include <cctype>
#include <cwctype>

// ===== Helpers =====
using namespace std::chrono;
static inline uint64_t qpc() { LARGE_INTEGER li; QueryPerformanceCounter(&li); return (uint64_t)li.QuadPart; }
static inline double qpc_ms(uint64_t ticks) { LARGE_INTEGER f; QueryPerformanceFrequency(&f); return 1000.0 * (double)ticks / (double)f.QuadPart; }
static std::mt19937 g_rng{ std::random_device{}() };

static std::string iso_time() {
    std::time_t t = std::time(nullptr); std::tm tm{}; localtime_s(&tm, &t);
    char buf[32]; std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm); return buf;
}
static bool file_exists(const char* p) { DWORD a = GetFileAttributesA(p); return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY); }

// ===== SHA-256 (BCrypt) =====
static bool sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    BCRYPT_ALG_HANDLE hAlg = nullptr; BCRYPT_HASH_HANDLE hHash = nullptr; NTSTATUS s;
    DWORD objLen = 0, cb = 0; if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0) < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
    std::vector<uint8_t> obj(objLen);
    if (BCryptCreateHash(hAlg, &hHash, obj.data(), objLen, nullptr, 0, 0) < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
    if (BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0) < 0) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
    s = BCryptFinishHash(hHash, (PUCHAR)out, 32, 0);
    BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0);
    return s >= 0;
}

// ===== .text section =====
static bool get_text_section(uint8_t*& base, uint8_t*& text_begin, size_t& text_size) {
    HMODULE hMod = GetModuleHandleW(nullptr); if (!hMod) return false; base = (uint8_t*)hMod;
    auto dos = (IMAGE_DOS_HEADER*)base; if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = (IMAGE_NT_HEADERS*)((uint8_t*)base + dos->e_lfanew); if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        char name[9]{}; memcpy(name, sec[i].Name, 8);
        if (strncmp(name, ".text", 5) == 0) {
            text_begin = base + sec[i].VirtualAddress;
            text_size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
            return true;
        }
    }
    return false;
}

// ===== Obfuscated value =====
struct ObfInt {
    uint32_t enc{ 0 }, key{ 0 }, tag{ 0 };
    static constexpr uint32_t SECRET = 0xA5C3F17Bu;
    void set(int v, std::mt19937& rng) {
        key = rng(); enc = (uint32_t)v ^ key;
        uint32_t buf[3] = { key, enc, SECRET }; uint8_t dig[32];
        sha256((uint8_t*)buf, sizeof(buf), dig); memcpy(&tag, dig, sizeof(tag));
    }
    bool ok() const {
        uint32_t buf[3] = { key, enc, SECRET }; uint8_t dig[32], t[4];
        if (!sha256((uint8_t*)buf, sizeof(buf), dig)) return false;
        memcpy(t, dig, sizeof(t)); return *(uint32_t*)t == tag;
    }
    int get() const { if (!ok()) return -1337; return (int)(enc ^ key); }
    void repair_from_plain(int plain, std::mt19937& rng) { set(plain, rng); }
};

// ===== Game State =====
struct GameState {
    // plain (stage-1)
    volatile int hp_plain{ 70 }, gold_plain{ 30 }, score_plain{ 0 };
    // protected on heap (addresses can move)
    ObfInt* hp_prot{ nullptr }; ObfInt* gold_prot{ nullptr }; ObfInt* score_prot{ nullptr };

    bool defenses_on{ false }, logging_on{ true }, relocation_enabled{ true };

    // watchdog
    std::atomic<bool> stop{ false };
    std::atomic<uint64_t> wd_ticks{ 0 }, wd_runs{ 0 };

    // detections / telemetry
    std::atomic<uint32_t> det_obf_mismatch{ 0 }, det_code_sha{ 0 }, det_debugger{ 0 }, det_proc_ce{ 0 }, det_plain_suspect{ 0 };

    // plain-change monitor (anti-freeze heuristic)
    std::atomic<bool> hp_plain_expected{ false }, gold_plain_expected{ false }, score_plain_expected{ false };
    int last_hp_plain{ 70 }, last_gold_plain{ 30 }, last_score_plain{ 0 };

    // relocation
    uint32_t reloc_interval_events{ 5 }; uint32_t events_since_reloc{ 0 };

    // SHA baseline
    uint8_t text_sha_baseline[32]{};

    // CSV
    std::ofstream log;
} g;

static void sync_prot_from_plain() {
    if (!g.hp_prot) g.hp_prot = new ObfInt();
    if (!g.gold_prot) g.gold_prot = new ObfInt();
    if (!g.score_prot) g.score_prot = new ObfInt();
    g.hp_prot->set(g.hp_plain, g_rng);
    g.gold_prot->set(g.gold_plain, g_rng);
    g.score_prot->set(g.score_plain, g_rng);
}

// ===== CSV logging (binary + \r\n for Excel friendliness) =====
static void log_line(const char* phase, double wd_ms) {
    if (!g.logging_on) return;
    if (!g.log.is_open()) {
        bool existed = file_exists("anticheat_log.csv");
        g.log.open("anticheat_log.csv", std::ios::app | std::ios::binary);
        if (!existed) g.log << "ts,phase,defenses,wd_ms_avg,wd_runs,obf,code_sha,debugger,proc_ce,plain_sus,hp,gold,score\r\n";
    }
    int hp = g.defenses_on && g.hp_prot ? g.hp_prot->get() : g.hp_plain;
    int gold = g.defenses_on && g.gold_prot ? g.gold_prot->get() : g.gold_plain;
    int sc = g.defenses_on && g.score_prot ? g.score_prot->get() : g.score_plain;
    g.log << iso_time() << ',' << phase << ',' << (g.defenses_on ? 1 : 0) << ','
        << std::fixed << std::setprecision(3) << wd_ms << ',' << g.wd_runs.load() << ','
        << g.det_obf_mismatch.load() << ',' << g.det_code_sha.load() << ','
        << g.det_debugger.load() << ',' << g.det_proc_ce.load() << ','
        << g.det_plain_suspect.load() << ',' << hp << ',' << gold << ',' << sc << "\r\n";
    g.log.flush();
}

// ===== Process scan for Cheat Engine (ANSI/UNICODE both OK) =====
static void scan_processes_for_ce() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe{ sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
#ifdef UNICODE
            std::wstring exe = pe.szExeFile;
            for (auto& ch : exe) ch = (wchar_t)towlower(ch);
            if (exe.find(L"cheatengine") != std::wstring::npos) { g.det_proc_ce++; break; }
#else
            std::string exe = pe.szExeFile;
            for (auto& ch : exe) ch = (char)tolower((unsigned char)ch);
            if (exe.find("cheatengine") != std::string::npos) { g.det_proc_ce++; break; }
#endif
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

// ===== Relocation =====
static void relocate_protected() {
    if (!g.defenses_on) return;
    int hp = g.hp_prot ? g.hp_prot->get() : g.hp_plain; if (hp < 0) hp = g.hp_plain;
    int gd = g.gold_prot ? g.gold_prot->get() : g.gold_plain; if (gd < 0) gd = g.gold_plain;
    int sc = g.score_prot ? g.score_prot->get() : g.score_plain; if (sc < 0) sc = g.score_plain;
    delete g.hp_prot; delete g.gold_prot; delete g.score_prot;
    g.hp_prot = new ObfInt(); g.gold_prot = new ObfInt(); g.score_prot = new ObfInt();
    g.hp_prot->set(hp, g_rng); g.gold_prot->set(gd, g_rng); g.score_prot->set(sc, g_rng);
}

// ===== Watchdog =====
static void watchdog() {
    uint8_t* base = nullptr, * text = nullptr; size_t text_sz = 0; get_text_section(base, text, text_sz);
    if (text) sha256(text, text_sz, g.text_sha_baseline);
    std::uniform_int_distribution<int> jitter(150, 350); // ms

    while (!g.stop.load()) {
        const uint64_t t0 = qpc();
        if (text) { uint8_t cur[32]; sha256(text, text_sz, cur); if (memcmp(cur, g.text_sha_baseline, 32) != 0) g.det_code_sha++; }
        if (IsDebuggerPresent()) g.det_debugger++;
        static auto last_scan = steady_clock::now();
        if (duration_cast<milliseconds>(steady_clock::now() - last_scan).count() > 1000) { scan_processes_for_ce(); last_scan = steady_clock::now(); }
        if (g.defenses_on) {
            if (g.hp_prot && !g.hp_prot->ok()) { g.det_obf_mismatch++; g.hp_prot->repair_from_plain(g.hp_plain, g_rng); }
            if (g.gold_prot && !g.gold_prot->ok()) { g.det_obf_mismatch++; g.gold_prot->repair_from_plain(g.gold_plain, g_rng); }
            if (g.score_prot && !g.score_prot->ok()) { g.det_obf_mismatch++; g.score_prot->repair_from_plain(g.score_plain, g_rng); }
            // anti-freeze heuristic
            if (g.hp_plain != g.last_hp_plain) { if (!g.hp_plain_expected.load()) g.det_plain_suspect++; g.last_hp_plain = g.hp_plain; g.hp_plain_expected.store(false); }
            if (g.gold_plain != g.last_gold_plain) { if (!g.gold_plain_expected.load()) g.det_plain_suspect++; g.last_gold_plain = g.gold_plain; g.gold_plain_expected.store(false); }
            if (g.score_plain != g.last_score_plain) { if (!g.score_plain_expected.load()) g.det_plain_suspect++; g.last_score_plain = g.score_plain; g.score_plain_expected.store(false); }
        }
        const uint64_t t1 = qpc(); g.wd_ticks += (t1 - t0); g.wd_runs++;
        double avg = g.wd_runs ? qpc_ms(g.wd_ticks) / (double)g.wd_runs : 0.0;
        log_line("tick", avg);

        static auto last_reloc = steady_clock::now();
        if (g.relocation_enabled && g.defenses_on) {
            if (g.events_since_reloc >= g.reloc_interval_events || duration_cast<seconds>(steady_clock::now() - last_reloc).count() >= 5) {
                relocate_protected(); g.events_since_reloc = 0; last_reloc = steady_clock::now();
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(jitter(g_rng)));
    }
}

// ===== Gameplay helpers =====
static void init_game() {
    g.defenses_on = false; g.logging_on = true;
    g.hp_plain = 70; g.gold_plain = 30; g.score_plain = 0;
    sync_prot_from_plain();
    g.last_hp_plain = g.hp_plain; g.last_gold_plain = g.gold_plain; g.last_score_plain = g.score_plain;
}
static void use_potion() {
    if (g.defenses_on) {
        int v = g.hp_prot ? g.hp_prot->get() : g.hp_plain; if (v < 0) v = g.hp_plain; v = std::min(v + 20, 100);
        if (g.hp_prot) g.hp_prot->set(v, g_rng); g.hp_plain_expected.store(true); g.hp_plain = v;
    }
    else { g.hp_plain = std::min(g.hp_plain + 20, 100); }
}
static void take_damage(int d) {
    if (g.defenses_on) {
        int v = g.hp_prot ? g.hp_prot->get() : g.hp_plain; if (v < 0) v = g.hp_plain; v = std::max(0, v - d);
        if (g.hp_prot) g.hp_prot->set(v, g_rng); g.hp_plain_expected.store(true); g.hp_plain = v;
    }
    else { g.hp_plain = std::max(0, g.hp_plain - d); }
}
static void add_gold(int x) {
    if (g.defenses_on) {
        int v = g.gold_prot ? g.gold_prot->get() : g.gold_plain; if (v < 0) v = g.gold_plain; v = std::max(0, v + x);
        if (g.gold_prot) g.gold_prot->set(v, g_rng); g.gold_plain_expected.store(true); g.gold_plain = v;
    }
    else { g.gold_plain = std::max(0, g.gold_plain + x); }
}
static void add_score(int x) {
    if (g.defenses_on) {
        int v = g.score_prot ? g.score_prot->get() : g.score_plain; if (v < 0) v = g.score_plain; v = std::max(0, v + x);
        if (g.score_prot) g.score_prot->set(v, g_rng); g.score_plain_expected.store(true); g.score_plain = v;
    }
    else { g.score_plain = std::max(0, g.score_plain + x); }
}

// ===== SDL text helper =====
static SDL_Texture* renderText(SDL_Renderer* R, TTF_Font* font, const std::string& text, SDL_Color color) {
    SDL_Surface* s = TTF_RenderUTF8_Blended(font, text.c_str(), color);
    if (!s) return nullptr; SDL_Texture* tex = SDL_CreateTextureFromSurface(R, s); SDL_FreeSurface(s); return tex;
}
static void drawText(SDL_Renderer* R, TTF_Font* font, int x, int y, const std::string& text, SDL_Color c) {
    SDL_Texture* t = renderText(R, font, text, c); if (!t) return;
    int w, h; SDL_QueryTexture(t, nullptr, nullptr, &w, &h); SDL_Rect dst{ x,y,w,h }; SDL_RenderCopy(R, t, nullptr, &dst); SDL_DestroyTexture(t);
}
static void drawBar(SDL_Renderer* R, int x, int y, int w, int h, float pct) {
    SDL_Rect bg{ x,y,w,h }; SDL_SetRenderDrawColor(R, 40, 40, 40, 255); SDL_RenderFillRect(R, &bg);
    int ww = std::max(0, std::min(w, (int)(w * pct)));
    SDL_Rect fg{ x,y,ww,h }; SDL_SetRenderDrawColor(R, 200, 30, 30, 255); SDL_RenderFillRect(R, &fg);
    SDL_SetRenderDrawColor(R, 200, 200, 200, 255); SDL_RenderDrawRect(R, &bg);
}

int main(int, char**) {
    // Init game & baseline SHA
    init_game();
    uint8_t* b = nullptr, * t = nullptr; size_t tsz = 0; if (get_text_section(b, t, tsz)) sha256(t, tsz, g.text_sha_baseline);

    // Init SDL
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0) { printf("SDL_Init failed: %s\n", SDL_GetError()); return 1; }
    if (TTF_Init() != 0) { printf("TTF_Init failed: %s\n", TTF_GetError()); return 1; }

    SDL_Window* W = SDL_CreateWindow("AntiCheat Prototype (SDL2) ¡ª Enhanced",
        SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 960, 540, SDL_WINDOW_SHOWN);
    SDL_Renderer* R = SDL_CreateRenderer(W, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!W || !R) { printf("SDL_CreateWindow/Renderer failed\n"); return 1; }

    // Load font (you can replace with your own .ttf path)
    const char* fontPath = "C:\\\\Windows\\\\Fonts\\\\consola.ttf";
    TTF_Font* font = TTF_OpenFont(fontPath, 20);
    if (!font) {
        // fallback: try a local font file
        font = TTF_OpenFont("consola.ttf", 20);
        if (!font) { printf("OpenFont failed; text will not render.\n"); }
    }

    // Start watchdog
    std::thread th(watchdog);

    bool running = true, showAddr = false; auto showAddrUntil = steady_clock::now();
    while (running) {
        // ---- Input ----
        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            if (e.type == SDL_QUIT) running = false;
            if (e.type == SDL_KEYDOWN) {
                SDL_Keycode k = e.key.keysym.sym;
                if (k == SDLK_ESCAPE || k == 'q') running = false;
                else if (k == 't') { g.defenses_on = !g.defenses_on; sync_prot_from_plain(); g.events_since_reloc = 0; }
                else if (k == 'e') {
                    int r = (int)(g_rng() % 100);
                    if (r < 50) { int dmg = 5 + (g_rng() % 11); take_damage(dmg); int coins = 5 + (g_rng() % 16); add_gold(coins); add_score(10); }
                    else if (r < 80) { int coins = 5 + (g_rng() % 16); add_gold(coins); add_score(5); }
                    else { int dmg = 3 + (g_rng() % 8); take_damage(dmg); }
                    int curHP = g.defenses_on && g.hp_prot ? g.hp_prot->get() : g.hp_plain;
                    if (curHP <= 0) {
                        // Respawn
                        if (g.defenses_on) { if (g.hp_prot) g.hp_prot->set(70, g_rng); g.hp_plain_expected.store(true); g.hp_plain = 70; }
                        else g.hp_plain = 70; add_gold(-10);
                    }
                    if (g.defenses_on) g.events_since_reloc++;
                }
                else if (k == 'b') { int curGold = g.defenses_on && g.gold_prot ? g.gold_prot->get() : g.gold_plain; if (curGold >= 10) { add_gold(-10); use_potion(); } }
                else if (k == 'r') { relocate_protected(); }
                else if (k == 'l') { g.logging_on = !g.logging_on; }
                else if (k == 'a') { showAddr = true; showAddrUntil = steady_clock::now() + seconds(3); }
            }
        }
        if (showAddr && steady_clock::now() > showAddrUntil) showAddr = false;

        // ---- Render ----
        SDL_SetRenderDrawColor(R, 18, 18, 22, 255); SDL_RenderClear(R);
        int hp = g.defenses_on && g.hp_prot ? g.hp_prot->get() : g.hp_plain; hp = std::max(0, std::min(100, hp));
        int gd = g.defenses_on && g.gold_prot ? g.gold_prot->get() : g.gold_plain;
        int sc = g.defenses_on && g.score_prot ? g.score_prot->get() : g.score_plain;

        // HP bar
        drawBar(R, 40, 40, 400, 26, hp / 100.0f);
        if (font) {
            drawText(R, font, 48, 42, "HP: " + std::to_string(hp) + "/100", SDL_Color{ 255,255,255,255 });
            drawText(R, font, 40, 80, "Gold: " + std::to_string(gd), SDL_Color{ 230,230,230,255 });
            drawText(R, font, 40, 110, "Score: " + std::to_string(sc), SDL_Color{ 230,230,230,255 });

            std::string mode = std::string("Mode: ") + (g.defenses_on ? "DEFENSES ON" : "DEFENSES OFF");
            std::string log = std::string("Log : ") + (g.logging_on ? "ON (anticheat_log.csv)" : "OFF");
            drawText(R, font, 40, 150, mode, SDL_Color{ 200,220,255,255 });
            drawText(R, font, 40, 180, log, SDL_Color{ 200,220,255,255 });

            double avg = g.wd_runs ? qpc_ms(g.wd_ticks) / (double)g.wd_runs : 0.0;
            drawText(R, font, 40, 230, "Watchdog avg cost: " + std::to_string(avg) + " ms", SDL_Color{ 200,200,200,255 });

            char det[256];
            std::snprintf(det, sizeof(det), "Detections: obf=%u  code_sha=%u  debugger=%u  proc_ce=%u  plain_sus=%u",
                g.det_obf_mismatch.load(), g.det_code_sha.load(), g.det_debugger.load(), g.det_proc_ce.load(), g.det_plain_suspect.load());
            drawText(R, font, 40, 260, det, SDL_Color{ 220,200,180,255 });

            // instructions
            drawText(R, font, 40, 320, "[E] Explore   [B] Buy Potion  [T] Toggle Defenses", SDL_Color{ 180,180,180,255 });
            drawText(R, font, 40, 350, "[R] Relocate  [A] Show CE Addresses  [L] Logging  [Esc/Q] Quit", SDL_Color{ 180,180,180,255 });

            if (showAddr) {
                int y = 400;
                drawText(R, font, 40, y, "[DEBUG] CE addresses (4 Bytes unless noted):", SDL_Color{ 255,220,160,255 }); y += 24;
                char line[256];
                std::snprintf(line, sizeof(line), "hp_plain    @ %p (int)", (void*)&g.hp_plain);
                drawText(R, font, 40, y, line, SDL_Color{ 255,220,160,255 }); y += 22;
                std::snprintf(line, sizeof(line), "gold_plain  @ %p (int)", (void*)&g.gold_plain);
                drawText(R, font, 40, y, line, SDL_Color{ 255,220,160,255 }); y += 22;
                std::snprintf(line, sizeof(line), "score_plain @ %p (int)", (void*)&g.score_plain);
                drawText(R, font, 40, y, line, SDL_Color{ 255,220,160,255 }); y += 22;
                if (g.hp_prot) {
                    std::snprintf(line, sizeof(line), "hp_prot.enc    @ %p (uint32)", (void*)&g.hp_prot->enc);
                    drawText(R, font, 40, y, line, SDL_Color{ 255,220,160,255 }); y += 22;
                }
                if (g.gold_prot) {
                    std::snprintf(line, sizeof(line), "gold_prot.enc  @ %p (uint32)", (void*)&g.gold_prot->enc);
                    drawText(R, font, 40, y, line, SDL_Color{ 255,220,160,255 }); y += 22;
                }
                if (g.score_prot) {
                    std::snprintf(line, sizeof(line), "score_prot.enc @ %p (uint32)", (void*)&g.score_prot->enc);
                    drawText(R, font, 40, y, line, SDL_Color{ 255,220,160,255 }); y += 22;
                }
            }
        }

        SDL_RenderPresent(R);
        SDL_Delay(16); // ~60 FPS
    }

    g.stop = true; th.join();
    if (g.log.is_open()) g.log.close();
    if (font) TTF_CloseFont(font);
    SDL_DestroyRenderer(R); SDL_DestroyWindow(W);
    TTF_Quit(); SDL_Quit();
    return 0;
}
