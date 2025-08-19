// RunnerAC.cpp - Console Runner with Anti-Cheat (C++17 / Windows)
// Build (MSVC):
//   cl /std:c++17 /O2 /EHsc /DUNICODE /D_UNICODE RunnerAC.cpp /Fe:RunnerAC.exe /link Bcrypt.lib
// Operation: Move A/D left and right; Fast forward one shot; B Purchase medicine (10g); U usage (+20HP)
//      T switch protection; R relocation; L log switch; H displays the address; Q exits.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#pragma comment(lib,"Bcrypt.lib")

#include <conio.h>   // _kbhit, _getch
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <random>
#include <string>
#include <vector>
#include <thread>

using namespace std;
using namespace std::chrono;

// ======= small tool =======
static mt19937 g_rng{ random_device{}() };
static inline uint64_t qpc() { LARGE_INTEGER li; QueryPerformanceCounter(&li); return (uint64_t)li.QuadPart; }
static inline double qpc_ms(uint64_t t) { LARGE_INTEGER f; QueryPerformanceFrequency(&f); return 1000.0 * (double)t / (double)f.QuadPart; }
static string iso_time() { time_t t = time(nullptr); tm tm{}; localtime_s(&tm, &t); char b[32]; strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S", &tm); return b; }
static bool file_exists(const char* p) { DWORD a = GetFileAttributesA(p); return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY); }

// ======= SHA-256（BCrypt）=======
static bool sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    BCRYPT_ALG_HANDLE alg = nullptr; BCRYPT_HASH_HANDLE h = nullptr; DWORD objLen = 0, cb = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0) < 0) { BCryptCloseAlgorithmProvider(alg, 0); return false; }
    vector<uint8_t> obj(objLen);
    if (BCryptCreateHash(alg, &h, obj.data(), objLen, nullptr, 0, 0) < 0) { BCryptCloseAlgorithmProvider(alg, 0); return false; }
    if (BCryptHashData(h, (PUCHAR)data, (ULONG)len, 0) < 0) { BCryptDestroyHash(h); BCryptCloseAlgorithmProvider(alg, 0); return false; }
    auto s = BCryptFinishHash(h, (PUCHAR)out, 32, 0);
    BCryptDestroyHash(h); BCryptCloseAlgorithmProvider(alg, 0);
    return s >= 0;
}

// ======= Find the. text section =======
static bool get_text(uint8_t*& base, uint8_t*& text, size_t& sz) {
    HMODULE m = GetModuleHandleW(nullptr); if (!m) return false; base = (uint8_t*)m;
    auto dos = (IMAGE_DOS_HEADER*)base; if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew); if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char name[9]{}; memcpy(name, sec[i].Name, 8);
        if (strncmp(name, ".text", 5) == 0) { text = base + sec[i].VirtualAddress; sz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData; return true; }
    } return false;
}

// ======= Encryption value =======
struct ObfInt {
    uint32_t enc{ 0 }, key{ 0 }, tag{ 0 }; static constexpr uint32_t SECRET = 0xA5C3F17Bu;
    void set(int v, mt19937& rng) { key = rng(); enc = (uint32_t)v ^ key; uint32_t buf[3] = { key,enc,SECRET }; uint8_t dig[32]; sha256((uint8_t*)buf, sizeof(buf), dig); memcpy(&tag, dig, 4); }
    bool ok() const { uint32_t buf[3] = { key,enc,SECRET }; uint8_t dig[32]; if (!sha256((uint8_t*)buf, sizeof(buf), dig)) return false; uint32_t t; memcpy(&t, dig, 4); return t == tag; }
    int  get() const { return ok() ? (int)(enc ^ key) : -1337; }
    void repair_from_plain(int plain, mt19937& rng) { set(plain, rng); }
};

// ======= Game/Protection Status =======
struct Entity { int x, y; char ch; }; // '$' gold, '*' potion, '#' obstacles
struct GS {
    
    volatile int hp_plain{ 70 }, gold_plain{ 30 }, score_plain{ 0 };
    
    ObfInt* hp_prot{ nullptr }; ObfInt* gold_prot{ nullptr }; ObfInt* score_prot{ nullptr };

    // defense
    bool defenses_on{ false }, logging_on{ true }, relocation_enabled{ true };
    atomic<bool> stop{ false }; atomic<uint64_t> wd_ticks{ 0 }, wd_runs{ 0 };
    atomic<uint32_t> det_obf{ 0 }, det_code{ 0 }, det_dbg{ 0 }, det_proc_ce{ 0 }, det_plain_sus{ 0 };
    atomic<bool> hp_exp{ false }, gold_exp{ false }, score_exp{ false };
    int last_hp{ 70 }, last_gold{ 30 }, last_score{ 0 };
    uint32_t reloc_every{ 12 }, events_since{ 0 };
    uint8_t text_sha[32]{};
    ofstream log;

    // game
    static constexpr int W = 40, H = 18;
    int px = W / 2, py = H - 2;
    vector<Entity> ents; 
    int potions{ 0 };
    bool show_addr{ false };

    // screen (for dual buffering)
    int scrW = max(W + 2, 100);
    int scrH = H + 12;
} g;

static void sync_prot() { if (!g.hp_prot) g.hp_prot = new ObfInt(); if (!g.gold_prot) g.gold_prot = new ObfInt(); if (!g.score_prot) g.score_prot = new ObfInt(); g.hp_prot->set(g.hp_plain, g_rng); g.gold_prot->set(g.gold_plain, g_rng); g.score_prot->set(g.score_plain, g_rng); }

static void log_line(const char* phase, double wd_ms) {
    if (!g.logging_on) return;
    if (!g.log.is_open()) {
        bool ex = file_exists("anticheat_log.csv"); g.log.open("anticheat_log.csv", ios::app | ios::binary);
        if (!ex) g.log << "ts,phase,defenses,wd_ms_avg,wd_runs,obf,code_sha,debugger,proc_ce,plain_sus,hp,gold,score\r\n";
    }
    int hp = g.defenses_on && g.hp_prot ? g.hp_prot->get() : g.hp_plain;
    int gd = g.defenses_on && g.gold_prot ? g.gold_prot->get() : g.gold_plain;
    int sc = g.defenses_on && g.score_prot ? g.score_prot->get() : g.score_plain;
    g.log << iso_time() << ',' << phase << ',' << (g.defenses_on ? 1 : 0) << ',' << fixed << setprecision(3) << wd_ms << ',' << g.wd_runs.load() << ','
        << g.det_obf.load() << ',' << g.det_code.load() << ',' << g.det_dbg.load() << ',' << g.det_proc_ce.load() << ',' << g.det_plain_sus.load()
        << ',' << hp << ',' << gd << ',' << sc << "\r\n";
    g.log.flush();
}

// Process scanning CE
static void scan_ce() {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); if (s == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe{ sizeof(pe) };
    if (Process32First(s, &pe)) {
        do {
#ifdef UNICODE
            wstring exe = pe.szExeFile; for (auto& c : exe) c = (wchar_t)towlower(c);
            if (exe.find(L"cheatengine") != wstring::npos) { g.det_proc_ce++; break; }
#else
            string exe = pe.szExeFile; for (auto& c : exe) c = (char)tolower((unsigned char)c);
            if (exe.find("cheatengine") != string::npos) { g.det_proc_ce++; break; }
#endif
        } while (Process32Next(s, &pe));
    }
    CloseHandle(s);
}

static void relocate() {
    if (!g.defenses_on) return;
    int hp = g.hp_prot ? g.hp_prot->get() : g.hp_plain; if (hp < 0) hp = g.hp_plain;
    int gd = g.gold_prot ? g.gold_prot->get() : g.gold_plain; if (gd < 0) gd = g.gold_plain;
    int sc = g.score_prot ? g.score_prot->get() : g.score_plain; if (sc < 0) sc = g.score_plain;
    delete g.hp_prot; delete g.gold_prot; delete g.score_prot;
    g.hp_prot = new ObfInt(); g.gold_prot = new ObfInt(); g.score_prot = new ObfInt();
    g.hp_prot->set(hp, g_rng); g.gold_prot->set(gd, g_rng); g.score_prot->set(sc, g_rng);
}

static void watchdog() {
    uint8_t* b = nullptr, * t = nullptr; size_t sz = 0; get_text(b, t, sz); if (t) sha256(t, sz, g.text_sha);
    uniform_int_distribution<int> jitter(150, 350);
    while (!g.stop.load()) {
        uint64_t t0 = qpc();
        if (t) { uint8_t cur[32]; sha256(t, sz, cur); if (memcmp(cur, g.text_sha, 32) != 0) g.det_code++; }
        if (IsDebuggerPresent()) g.det_dbg++;
        static auto last = steady_clock::now();
        if (duration_cast<milliseconds>(steady_clock::now() - last).count() > 1000) { scan_ce(); last = steady_clock::now(); }

        if (g.defenses_on) {
            if (g.hp_prot && !g.hp_prot->ok()) { g.det_obf++; g.hp_prot->repair_from_plain(g.hp_plain, g_rng); }
            if (g.gold_prot && !g.gold_prot->ok()) { g.det_obf++; g.gold_prot->repair_from_plain(g.gold_plain, g_rng); }
            if (g.score_prot && !g.score_prot->ok()) { g.det_obf++; g.score_prot->repair_from_plain(g.score_plain, g_rng); }
            if (g.hp_plain != g.last_hp) { if (!g.hp_exp.load()) g.det_plain_sus++; g.last_hp = g.hp_plain; g.hp_exp.store(false); }
            if (g.gold_plain != g.last_gold) { if (!g.gold_exp.load()) g.det_plain_sus++; g.last_gold = g.gold_plain; g.gold_exp.store(false); }
            if (g.score_plain != g.last_score) { if (!g.score_exp.load()) g.det_plain_sus++; g.last_score = g.score_plain; g.score_exp.store(false); }
        }
        uint64_t t1 = qpc(); g.wd_ticks += (t1 - t0); g.wd_runs++;
        double avg = g.wd_runs ? qpc_ms(g.wd_ticks) / (double)g.wd_runs : 0.0; log_line("tick", avg);

        static auto last_reloc = steady_clock::now();
        if (g.relocation_enabled && g.defenses_on) {
            if (g.events_since >= g.reloc_every || duration_cast<seconds>(steady_clock::now() - last_reloc).count() >= 6) {
                relocate(); g.events_since = 0; last_reloc = steady_clock::now();
            }
        }
        this_thread::sleep_for(milliseconds(jitter(g_rng)));
    }
}

// ======= game logic =======
static void add_gold(int v) { if (g.defenses_on) { int t = g.gold_prot ? g.gold_prot->get() : g.gold_plain; if (t < 0) t = g.gold_plain; t = max(0, t + v); if (g.gold_prot) g.gold_prot->set(t, g_rng); g.gold_exp.store(true); g.gold_plain = t; } else g.gold_plain = max(0, g.gold_plain + v); }
static void add_score(int v) { if (g.defenses_on) { int t = g.score_prot ? g.score_prot->get() : g.score_plain; if (t < 0) t = g.score_plain; t = max(0, t + v); if (g.score_prot) g.score_prot->set(t, g_rng); g.score_exp.store(true); g.score_plain = t; } else g.score_plain = max(0, g.score_plain + v); }
static void damage(int d) { if (g.defenses_on) { int t = g.hp_prot ? g.hp_prot->get() : g.hp_plain; if (t < 0) t = g.hp_plain; t = max(0, t - d); if (g.hp_prot) g.hp_prot->set(t, g_rng); g.hp_exp.store(true); g.hp_plain = t; } else g.hp_plain = max(0, g.hp_plain - d); }
static void heal(int d) { if (g.defenses_on) { int t = g.hp_prot ? g.hp_prot->get() : g.hp_plain; if (t < 0) t = g.hp_plain; t = min(100, t + d); if (g.hp_prot) g.hp_prot->set(t, g_rng); g.hp_exp.store(true); g.hp_plain = t; } else g.hp_plain = min(100, g.hp_plain + d); }

static void spawn_row() {
    
    uniform_int_distribution<int> X(1, g.W - 2);
    int n = 1 + (g_rng() % 3); // 1~3 个
    for (int i = 0; i < n; i++) {
        int r = g_rng() % 10;
        char ch = (r < 5) ? '#' : (r < 8 ? '$' : '*');
        g.ents.push_back({ X(g_rng), 1, ch });
    }
}
static void tick_fall() {
    for (auto& e : g.ents) e.y++;
    
    vector<Entity> next;
    for (auto& e : g.ents) {
        if (e.y == g.py && e.x == g.px) {
            if (e.ch == '#') { damage(7 + (g_rng() % 5)); }
            else if (e.ch == '$') { add_gold(5 + (g_rng() % 11)); add_score(5); }
            else if (e.ch == '*') { g.potions++; add_score(2); }
        }
        else if (e.y < g.H - 1) {
            next.push_back(e);
        }
        else {
            if (e.ch == '#') add_score(1);
        }
    }
    g.ents.swap(next);
}

// ======= Double buffer rendering（WriteConsoleOutputA） =======
static void draw_screen() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    const int W = g.scrW, H = g.scrH;
    vector<CHAR_INFO> buf(W * H);
    
    WORD colText = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    for (int i = 0; i < W * H; i++) { buf[i].Char.AsciiChar = ' '; buf[i].Attributes = colText; }
    auto putc_at = [&](int x, int y, char c, WORD a = colText) {
        if (x < 0 || y < 0 || x >= W || y >= H) return;
        buf[y * W + x].Char.AsciiChar = c;
        buf[y * W + x].Attributes = a;
        };
    auto text_at = [&](int x, int y, const string& s, WORD a = colText) {
        for (size_t i = 0; i < s.size(); ++i) putc_at(x + (int)i, y, s[i], a);
        };

    
    const int ox = 1, oy = 1;
    WORD colBorder = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    WORD colWall = FOREGROUND_RED | FOREGROUND_INTENSITY;
    WORD colGold = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    WORD colPotion = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    WORD colPlayer = FOREGROUND_GREEN | FOREGROUND_INTENSITY;

    
    for (int x = 0; x < g.W; x++) { putc_at(ox + x, oy - 1, '='); putc_at(ox + x, oy + g.H, '='); }
    for (int y = 0; y < g.H; y++) { putc_at(ox - 1, oy + y, '|'); putc_at(ox + g.W, oy + y, '|'); }
    for (int x = 0; x < g.W; x++) { putc_at(ox + x, oy - 1, '=', colBorder); putc_at(ox + x, oy + g.H, '=', colBorder); }
    for (int y = 0; y < g.H; y++) { putc_at(ox - 1, oy + y, '|', colBorder); putc_at(ox + g.W, oy + y, '|', colBorder); }

    
    for (auto& e : g.ents) {
        if (e.y > 0 && e.y < g.H - 1) {
            WORD col = (e.ch == '#') ? colWall : (e.ch == '$' ? colGold : colPotion);
            putc_at(ox + e.x, oy + e.y, e.ch, col);
        }
    }
    
    putc_at(ox + g.px, oy + g.py, 'P', colPlayer);

    
    int hp = g.defenses_on && g.hp_prot ? g.hp_prot->get() : g.hp_plain;
    int gd = g.defenses_on && g.gold_prot ? g.gold_prot->get() : g.gold_plain;
    int sc = g.defenses_on && g.score_prot ? g.score_prot->get() : g.score_plain;
    double avg = g.wd_runs ? qpc_ms(g.wd_ticks) / (double)g.wd_runs : 0.0;

    int y = oy + g.H + 1;
    text_at(1, y++, string("Mode: ") + (g.defenses_on ? "ON" : "OFF") + "   Log: " + (g.logging_on ? "ON" : "OFF"));
    {
        char line[128];
        _snprintf_s(line, sizeof(line), "HP:%d/100  Gold:%d  Score:%d  Potions:%d", max(0, min(100, hp)), gd, sc, g.potions);
        text_at(1, y++, line);
        _snprintf_s(line, sizeof(line), "Watchdog avg: %.3f ms   Detect: obf=%u code=%u dbg=%u proc_ce=%u plain=%u",
            avg, g.det_obf.load(), g.det_code.load(), g.det_dbg.load(), g.det_proc_ce.load(), g.det_plain_sus.load());
        text_at(1, y++, line);
    }
    text_at(1, y++, "[A/D] Move  [E] Step  [B] Buy(10g)  [U] Use  [T] Def  [R] Reloc  [L] Log  [H] Addresses  [Q] Quit");

    if (g.show_addr) {
        text_at(1, y++, "[DEBUG] CE addresses (4 bytes unless noted):");
        char b[128];
        _snprintf_s(b, sizeof(b), "  hp_plain   @ %p (int)", (void*)&g.hp_plain); text_at(1, y++, b);
        _snprintf_s(b, sizeof(b), "  gold_plain @ %p (int)", (void*)&g.gold_plain); text_at(1, y++, b);
        _snprintf_s(b, sizeof(b), "  score_plain@ %p (int)", (void*)&g.score_plain); text_at(1, y++, b);
        if (g.hp_prot) { _snprintf_s(b, sizeof(b), "  hp_prot.enc   @ %p (uint32)", (void*)&g.hp_prot->enc); text_at(1, y++, b); }
        if (g.gold_prot) { _snprintf_s(b, sizeof(b), "  gold_prot.enc @ %p (uint32)", (void*)&g.gold_prot->enc); text_at(1, y++, b); }
        if (g.score_prot) { _snprintf_s(b, sizeof(b), "  score_prot.enc@ %p (uint32)", (void*)&g.score_prot->enc); text_at(1, y++, b); }
        text_at(1, y++, "Press H to hide addresses.");
    }

    // Write at once (smooth refresh)
    COORD bufferSize{ (SHORT)W, (SHORT)H };
    COORD bufferCoord{ 0,0 };
    SMALL_RECT writeRegion{ 0,0, (SHORT)(W - 1), (SHORT)(H - 1) };
    WriteConsoleOutputA(hOut, buf.data(), bufferSize, bufferCoord, &writeRegion);
}

// ======= main program =======
int main() {
    
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    // initialization
    g.defenses_on = false; g.logging_on = true;
    g.hp_plain = 70; g.gold_plain = 30; g.score_plain = 0; g.px = g.W / 2; g.py = g.H - 2; g.ents.clear();
    sync_prot(); g.last_hp = g.hp_plain; g.last_gold = g.gold_plain; g.last_score = g.score_plain;

    // Code integrity baseline
    uint8_t* b = nullptr, * t = nullptr; size_t tsz = 0; if (get_text(b, t, tsz)) sha256(t, tsz, g.text_sha);

    // Align the buffer with the window (avoid right/bottom ghosting)
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD size = { (SHORT)g.scrW, (SHORT)g.scrH };
    SetConsoleScreenBufferSize(hOut, size);
    SMALL_RECT rect{ 0,0,(SHORT)(size.X - 1),(SHORT)(size.Y - 1) };
    SetConsoleWindowInfo(hOut, TRUE, &rect);

    thread th(watchdog);

    auto lastSpawn = steady_clock::now();
    bool running = true;

    while (running) {
        
        if (_kbhit()) {
            int c = _getch();
            if (c == 'q' || c == 'Q') running = false;
            else if (c == 'a' || c == 'A') { g.px = max(1, g.px - 1); }
            else if (c == 'd' || c == 'D') { g.px = min(g.W - 2, g.px + 1); }
            else if (c == 'e' || c == 'E') { /*额外推进一拍*/ spawn_row(); tick_fall(); add_score(1); if (g.defenses_on) g.events_since++; }
            else if (c == 'b' || c == 'B') { int gold = g.defenses_on && g.gold_prot ? g.gold_prot->get() : g.gold_plain; if (gold >= 10) { add_gold(-10); g.potions++; } }
            else if (c == 'u' || c == 'U') { if (g.potions > 0) { g.potions--; heal(20); } }
            else if (c == 't' || c == 'T') { g.defenses_on = !g.defenses_on; sync_prot(); g.events_since = 0; }
            else if (c == 'r' || c == 'R') { relocate(); }
            else if (c == 'l' || c == 'L') { g.logging_on = !g.logging_on; }
            else if (c == 'h' || c == 'H') { g.show_addr = !g.show_addr; }
        }

        // Automatic generation and descent (generated every~400ms)
        if (duration_cast<milliseconds>(steady_clock::now() - lastSpawn).count() > 400) {
            spawn_row(); lastSpawn = steady_clock::now(); add_score(1); if (g.defenses_on) g.events_since++;
        }
        tick_fall();

        // Resurrection of Death
        int hp = g.defenses_on && g.hp_prot ? g.hp_prot->get() : g.hp_plain;
        if (hp <= 0) { if (g.defenses_on) { if (g.hp_prot) g.hp_prot->set(70, g_rng); g.hp_exp.store(true); g.hp_plain = 70; } else g.hp_plain = 70; add_gold(-10); }

        draw_screen();
        Sleep(60); // About 1/3 of~16FPS, leaving CPU
    }

    g.stop = true; th.join(); if (g.log.is_open()) g.log.close();
    return 0;
}
