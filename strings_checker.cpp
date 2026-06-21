// StringsChecker — string-hash based cheat detector with GUI
//
// Full build (with server):
//   g++ -O2 -std=c++17 strings_checker.cpp -o StringsChecker.exe -lgdiplus -lpsapi -lntdll -lws2_32 -lshell32 -lcomdlg32 -ldwmapi -lwinhttp -mwindows -static
//
// Offline build (no server, no network deps):
//   g++ -O2 -std=c++17 -DNO_SERVER strings_checker.cpp -o StringsCheckerOffline.exe -lgdiplus -lpsapi -lntdll -lshell32 -lcomdlg32 -ldwmapi -mwindows -static
//
#define UNICODE
#define _UNICODE
#ifndef NO_SERVER
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <windows.h>
#ifndef NO_SERVER
#include <winhttp.h>
#endif
#include <gdiplus.h>
#include <dwmapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <commdlg.h>
#include <shellapi.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <unordered_set>
#include <unordered_map>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <algorithm>
#include <fstream>
#include <sstream>

using namespace Gdiplus;
#define WM_SCAN_TICK (WM_APP+1)
#define WM_SCAN_DONE (WM_APP+2)

// ======================== COLORS ========================
static const Color C_BG   (255, 13, 17, 23);
static const Color C_SURF (255, 22, 27, 34);
static const Color C_SURF2(255, 33, 38, 45);
static const Color C_BORD (255, 48, 54, 61);
static const Color C_TXT  (255,230,237,243);
static const Color C_TXT2 (255,139,148,158);
static const Color C_ACC  (255, 88,166,255);
static const Color C_ACC2 (255,121,192,255);
static const Color C_GRN  (255, 63,185, 80);
static const Color C_RED  (255,248, 81, 73);
static const Color C_YEL  (255,210,153, 34);

static const int W_W = 760, W_H = 640;
static const int TITLE_H = 42;

// ======================== FNV-1a (same as mc_inspect) ========================
static uint64_t fnv1a(const uint8_t* p, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}
static uint64_t fnv1a_s(const std::string& s) { return fnv1a((const uint8_t*)s.data(), s.size()); }

static std::string hexHash(uint64_t h) {
    char buf[20]; snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)h);
    return buf;
}
static uint64_t parseHex64(const std::string& s) { return strtoull(s.c_str(), nullptr, 16); }

// ======================== MINI JSON ========================
struct JVal {
    enum Type { NUL, STR, NUM, BOOL, ARR, OBJ } type = NUL;
    std::string s; double n = 0; bool b = false;
    std::vector<JVal> a;
    std::map<std::string, JVal> o;
    const JVal& operator[](const char* k) const { auto it=o.find(k); static JVal nil; return it!=o.end()?it->second:nil; }
    int size() const { return type==ARR?(int)a.size():0; }
};
static void jskip(const char*& p) { while(*p==' '||*p=='\t'||*p=='\n'||*p=='\r') p++; }
static std::string jstr(const char*& p) {
    if (*p!='"') return ""; p++;
    std::string s;
    while (*p && *p!='"') {
        if (*p=='\\') { p++; switch(*p){ case'"':s+='"';break; case'\\':s+='\\';break; case'n':s+='\n';break; case't':s+='\t';break; case'/':s+='/';break; default:s+=*p; } }
        else s+=*p;
        p++;
    }
    if (*p=='"') p++;
    return s;
}
static JVal jval(const char*& p);
static JVal jarr(const char*& p) {
    JVal v; v.type=JVal::ARR; p++; jskip(p);
    while(*p && *p!=']') { v.a.push_back(jval(p)); jskip(p); if(*p==',')p++; jskip(p); }
    if(*p==']')p++; return v;
}
static JVal jobj(const char*& p) {
    JVal v; v.type=JVal::OBJ; p++; jskip(p);
    while(*p && *p!='}') { std::string k=jstr(p); jskip(p); if(*p==':')p++; jskip(p); v.o[k]=jval(p); jskip(p); if(*p==',')p++; jskip(p); }
    if(*p=='}')p++; return v;
}
static JVal jval(const char*& p) {
    jskip(p);
    if(*p=='"'){JVal v;v.type=JVal::STR;v.s=jstr(p);return v;}
    if(*p=='[') return jarr(p);
    if(*p=='{') return jobj(p);
    if(*p=='t'){p+=4;JVal v;v.type=JVal::BOOL;v.b=true;return v;}
    if(*p=='f'){p+=5;JVal v;v.type=JVal::BOOL;v.b=false;return v;}
    if(*p=='n'){p+=4;return JVal();}
    JVal v;v.type=JVal::NUM;char*e;v.n=strtod(p,&e);p=e;return v;
}
static JVal jparse(const std::string& s) { const char* p=s.c_str(); return jval(p); }

// ======================== UTILITY ========================
static std::string readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    std::ostringstream ss; ss << f.rdbuf(); return ss.str();
}
static std::wstring toW(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8,0,s.c_str(),(int)s.size(),nullptr,0);
    std::wstring w(n, 0); MultiByteToWideChar(CP_UTF8,0,s.c_str(),(int)s.size(),&w[0],n);
    return w;
}
static std::string toU8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8,0,w.c_str(),(int)w.size(),nullptr,0,nullptr,nullptr);
    std::string s(n,0); WideCharToMultiByte(CP_UTF8,0,w.c_str(),(int)w.size(),&s[0],n,nullptr,nullptr);
    return s;
}
static std::string getExeDir() {
    char buf[MAX_PATH]; GetModuleFileNameA(nullptr, buf, MAX_PATH);
    char* p = strrchr(buf, '\\'); if (p) *(p+1)=0; return buf;
}

#ifndef NO_SERVER
// ======================== HWID ========================
static std::string getHWID() {
    HKEY key; char buf[256]={};  DWORD sz=sizeof(buf);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ|KEY_WOW64_64KEY, &key)==ERROR_SUCCESS) {
        RegQueryValueExA(key, "MachineGuid", nullptr, nullptr, (BYTE*)buf, &sz);
        RegCloseKey(key);
    }
    return hexHash(fnv1a((const uint8_t*)buf, strlen(buf)));
}

// ======================== HTTP CLIENT (WinHTTP — supports HTTPS) ========================
static std::string httpReq(const std::string& method, const std::string& host, int port,
                           const std::string& path, const std::string& body="", bool https=false) {
    std::wstring whost = toW(host), wpath = toW(path), wmethod = toW(method);
    HINTERNET hSes = WinHttpOpen(L"StringsChecker/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSes) return "";
    HINTERNET hCon = WinHttpConnect(hSes, whost.c_str(), (INTERNET_PORT)port, 0);
    if (!hCon) { WinHttpCloseHandle(hSes); return ""; }
    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hCon, wmethod.c_str(), wpath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return ""; }
    WinHttpSetTimeouts(hReq, 5000, 5000, 8000, 8000);
    WinHttpAddRequestHeaders(hReq, L"Content-Type: application/json", (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
    LPVOID bd = body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.c_str();
    BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        bd, (DWORD)body.size(), (DWORD)body.size(), 0);
    if (!ok || !WinHttpReceiveResponse(hReq, nullptr)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return "";
    }
    std::string result; DWORD nr=0; char buf[4096];
    while (WinHttpReadData(hReq, buf, sizeof(buf), &nr) && nr>0) { result.append(buf, nr); nr=0; }
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
    return result;
}
#endif // NO_SERVER

// ======================== TYPES ========================
struct DetectRule {
    std::string name, process;
    bool showStrings = true;
    std::vector<uint64_t> hashes;
    bool isServer = false;
};
struct DetectResult {
    std::string name, process, windowTitle;
    DWORD pid = 0;
    int found = 0, total = 0;
    bool showStrings = false;
    std::vector<std::string> foundStrings;
    bool isServer = false;
};
struct HistoryCheck {
    std::string timestamp;
    std::vector<DetectResult> results;
};

// ======================== DETECTS LOADING ========================
static std::vector<DetectRule> loadDetects(const std::string& json, bool server) {
    std::vector<DetectRule> out;
    JVal root = jparse(json);
    for (auto& d : root["detects"].a) {
        DetectRule r;
        r.name = d["name"].s;
        r.process = d["process"].s;
        r.showStrings = d["show_strings"].b;
        r.isServer = server;
        for (auto& h : d["hashes"].a) r.hashes.push_back(parseHex64(h.s));
        if (!r.name.empty() && !r.process.empty() && !r.hashes.empty()) out.push_back(r);
    }
    return out;
}

// ======================== STRING SCANNER ========================
static bool isTextCP(uint32_t cp) {
    if (cp>=0x20 && cp<0x7F) return true;
    if (cp>=0xA0 && cp<=0x24F) return true;
    if (cp>=0x370 && cp<=0x3FF) return true;
    if (cp>=0x400 && cp<=0x4FF) return true;
    if (cp>=0x500 && cp<=0x52F) return true;
    return false;
}

using StrCB = std::function<void(const std::string&)>;

static void scanUtf8(const uint8_t* b, size_t n, int minLen, const StrCB& cb) {
    size_t i=0;
    while (i<n) {
        size_t start=i; int cps=0;
        while (i<n) {
            uint8_t c=b[i]; uint32_t cp; size_t len;
            if (c<0x80){cp=c;len=1;}
            else if((c&0xE0)==0xC0){if(i+1>=n||(b[i+1]&0xC0)!=0x80)break;cp=((c&0x1F)<<6)|(b[i+1]&0x3F);len=2;if(cp<0x80)break;}
            else if((c&0xF0)==0xE0){if(i+2>=n||(b[i+1]&0xC0)!=0x80||(b[i+2]&0xC0)!=0x80)break;cp=((c&0x0F)<<12)|((b[i+1]&0x3F)<<6)|(b[i+2]&0x3F);len=3;if(cp<0x800)break;}
            else break;
            if(!isTextCP(cp))break;
            i+=len; cps++;
        }
        if(cps>=minLen) cb(std::string((const char*)b+start, i-start));
        if(i==start) i++;
    }
}

static void scanUtf16(const uint8_t* b, size_t n, int minLen, const StrCB& cb) {
    size_t i=0;
    while (i+1<n) {
        size_t start=i; std::wstring w;
        while (i+1<n) {
            uint16_t u=(uint16_t)(b[i]|(b[i+1]<<8));
            if(!isTextCP(u)) break;
            w.push_back((wchar_t)u); i+=2;
        }
        if((int)w.size()>=minLen) {
            int need=WideCharToMultiByte(CP_UTF8,0,w.c_str(),(int)w.size(),nullptr,0,nullptr,nullptr);
            if(need>0){std::string s((size_t)need,0);WideCharToMultiByte(CP_UTF8,0,w.c_str(),(int)w.size(),&s[0],need,nullptr,nullptr);cb(s);}
        }
        if(i==start) i++;
    }
}

static void scanProcess(HANDLE proc, int minLen, const StrCB& cb) {
    const size_t CH = 4*1024*1024;
    std::vector<uint8_t> buf(CH);
    MEMORY_BASIC_INFORMATION mbi{}; uintptr_t a=0;
    while (VirtualQueryEx(proc,(PVOID)a,&mbi,sizeof(mbi))==sizeof(mbi)) {
        uintptr_t base=(uintptr_t)mbi.BaseAddress; size_t rsz=(size_t)mbi.RegionSize;
        bool readable = (mbi.State==MEM_COMMIT) && !(mbi.Protect&PAGE_GUARD) &&
                        (mbi.Protect&0xFF)!=PAGE_NOACCESS && mbi.Protect!=0;
        if (readable && rsz) {
            size_t pos=0;
            while (pos<rsz) {
                size_t toRead=(std::min)(CH, rsz-pos); SIZE_T got=0;
                ReadProcessMemory(proc,(PVOID)(base+pos),buf.data(),toRead,&got);
                if(got){scanUtf8(buf.data(),got,minLen,cb);scanUtf16(buf.data(),got,minLen,cb);}
                pos += (got<toRead) ? (got+0x1000) : toRead;
            }
        }
        a=base+rsz; if(a==0) break;
    }
}

// ======================== APP STATE ========================
struct App {
    HWND hwnd = nullptr;
#ifndef NO_SERVER
    std::string hwid;
    std::string serverHost = "localhost";
    int serverPort = 8000;
    bool serverHttps = false;
    std::string serverBasePath;
    std::vector<DetectRule> serverRules;
    bool serverOnline = false;
    bool serverChecked = false;
    std::vector<HistoryCheck> history;
    bool hasHistory = false;
    bool showHistory = false;
    int expandedHist = -1;
    std::vector<RECT> histRects;
    RECT btnScanSrv{}, btnHistToggle{};
#endif

    std::vector<DetectRule> localRules;
    std::string localPath;

    std::vector<DetectResult> results;

    std::atomic<bool> scanning{false};
    std::atomic<int> scanPct{0};
    int scanMode = 0; // 1=server, 2=local
    std::string scanStatus;
    std::mutex statusMx;
    float spinAngle = 0;

    int scrollY = 0, maxScroll = 0;
    int expandedIdx = -1;

    RECT btnScanLocal{}, btnBrowse{}, btnClose{}, btnMin{}, btnCredit{};
    std::vector<RECT> resultRects;
    std::vector<int> resultMap;

    HCURSOR curHand, curArrow;
};
static App g;

#ifndef NO_SERVER
static std::string apiPath(const std::string& ep) { return g.serverBasePath + ep; }
static std::string srvGet(const std::string& ep)  { return httpReq("GET",g.serverHost,g.serverPort,apiPath(ep),"",g.serverHttps); }
static std::string srvPost(const std::string& ep, const std::string& body) { return httpReq("POST",g.serverHost,g.serverPort,apiPath(ep),body,g.serverHttps); }
#endif

// ======================== WINDOW TITLE ========================
struct WndFindCtx { DWORD pid; std::string title; };
static BOOL CALLBACK enumWndCb(HWND hw, LPARAM lp) {
    auto* ctx = (WndFindCtx*)lp;
    DWORD wp = 0; GetWindowThreadProcessId(hw, &wp);
    if (wp != ctx->pid || !IsWindowVisible(hw)) return TRUE;
    wchar_t buf[256] = {};
    SendMessageTimeoutW(hw, WM_GETTEXT, 256, (LPARAM)buf, SMTO_ABORTIFHUNG, 200, nullptr);
    if (buf[0]) { ctx->title = toU8(buf); return FALSE; }
    return TRUE;
}
static std::string getWindowTitle(DWORD pid) {
    WndFindCtx ctx{pid, {}};
    EnumWindows(enumWndCb, (LPARAM)&ctx);
    return ctx.title;
}

// ======================== PROCESS ENUM ========================
static std::vector<std::pair<DWORD,std::string>> findProcs(const std::string& name) {
    std::vector<std::pair<DWORD,std::string>> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap==INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe{}; pe.dwSize=sizeof(pe);
    if (Process32FirstW(snap,&pe)) do {
        char buf[260];
        WideCharToMultiByte(CP_UTF8,0,pe.szExeFile,-1,buf,sizeof(buf),0,0);
        if (_stricmp(buf, name.c_str())==0) out.push_back({pe.th32ProcessID, buf});
    } while(Process32NextW(snap,&pe));
    CloseHandle(snap);
    return out;
}

// ======================== SCAN THREAD ========================
static void doScan() {
    auto& A = g;
    A.results.clear();
    A.expandedIdx = -1;
    A.scrollY = 0;

    std::vector<DetectRule> all;
#ifndef NO_SERVER
    if (A.scanMode != 2) all.insert(all.end(), A.serverRules.begin(), A.serverRules.end());
#endif
    if (A.scanMode != 1) all.insert(all.end(), A.localRules.begin(), A.localRules.end());
    if (all.empty()) {
        { std::lock_guard<std::mutex> lk(A.statusMx); A.scanStatus=u8"Нет детектов для проверки"; }
        A.scanning = false;
        PostMessage(A.hwnd, WM_SCAN_DONE, 0, 0);
        return;
    }

    // group by process name
    std::map<std::string, std::vector<DetectRule*>> byProc;
    for (auto& r : all) {
        std::string low = r.process;
        for (auto& c:low) c=(char)tolower((unsigned char)c);
        byProc[low].push_back(&r);
    }

    int totalProcs = 0, doneProcs = 0;
    std::map<std::string, std::vector<std::pair<DWORD,std::string>>> procPids;
    for (auto& [pname, rules] : byProc) {
        auto pids = findProcs(pname);
        procPids[pname] = pids;
        totalProcs += (int)pids.size();
    }
    if (totalProcs==0) totalProcs=1;

    for (auto& [pname, rules] : byProc) {
        auto& pids = procPids[pname];
        if (pids.empty()) {
            for (auto* rule : rules) {
                DetectResult dr;
                dr.name=rule->name; dr.process=rule->process; dr.pid=0;
                dr.found=0; dr.total=(int)rule->hashes.size();
                dr.showStrings=rule->showStrings; dr.isServer=rule->isServer;
                A.results.push_back(dr);
            }
        }
        for (auto& [pid, exeName] : pids) {
            std::string wndTitle = getWindowTitle(pid);
            { std::lock_guard<std::mutex> lk(A.statusMx);
              A.scanStatus=exeName+" (PID: "+std::to_string(pid)+")"+(wndTitle.empty()?"":(" - "+wndTitle)); }

            HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, pid);
            if (!proc) {
                for (auto* rule : rules) {
                    DetectResult dr;
                    dr.name=rule->name; dr.process=exeName; dr.pid=pid; dr.windowTitle=wndTitle;
                    dr.found=0; dr.total=(int)rule->hashes.size();
                    dr.showStrings=rule->showStrings; dr.isServer=rule->isServer;
                    A.results.push_back(dr);
                }
                doneProcs++;
                A.scanPct = doneProcs*100/totalProcs;
                continue;
            }

            // build combined hash set for all rules targeting this process
            std::unordered_set<uint64_t> hashSet;
            for (auto* rule : rules)
                for (auto h : rule->hashes) hashSet.insert(h);

            // scan and collect matches
            std::unordered_map<uint64_t, std::string> found;
            scanProcess(proc, 4, [&](const std::string& s) {
                uint64_t h = fnv1a_s(s);
                if (hashSet.count(h) && !found.count(h)) found[h] = s;
            });
            CloseHandle(proc);

            // build results per rule
            for (auto* rule : rules) {
                DetectResult dr;
                dr.name=rule->name; dr.process=exeName; dr.pid=pid; dr.windowTitle=wndTitle;
                dr.total=(int)rule->hashes.size();
                dr.showStrings=rule->showStrings; dr.isServer=rule->isServer;
                for (auto rh : rule->hashes) {
                    auto it = found.find(rh);
                    if (it!=found.end()) {
                        dr.found++;
                        if (rule->showStrings) dr.foundStrings.push_back(it->second);
                    }
                }
                A.results.push_back(dr);
            }
            doneProcs++;
            A.scanPct = doneProcs*100/totalProcs;
        }
    }

#ifndef NO_SERVER
    // post server results (only for server scan mode)
    if (A.serverOnline && A.scanMode == 1) {
        std::string json = "{\"timestamp\":\"" + [] {
            char buf[32]; SYSTEMTIME st; GetLocalTime(&st);
            snprintf(buf,sizeof(buf),"%04d-%02d-%02d %02d:%02d:%02d",st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond);
            return std::string(buf);
        }() + "\",\"results\":[";
        bool first = true;
        for (auto& r : A.results) {
            if (!r.isServer) continue;
            if (!first) json+=","; first=false;
            json+="{\"name\":\""+r.name+"\",\"process\":\""+r.process+"\",\"pid\":"+std::to_string(r.pid)+
                  ",\"found\":"+std::to_string(r.found)+",\"total\":"+std::to_string(r.total)+"}";
        }
        json+="]}";
        srvPost("/results/"+A.hwid, json);
    }
#endif

    { std::lock_guard<std::mutex> lk(A.statusMx); A.scanStatus=u8"Готово"; }
    A.scanning = false;
    PostMessage(A.hwnd, WM_SCAN_DONE, 0, 0);
}

// ======================== GUI HELPERS ========================
static void FillRR(Graphics& g, const Color& c, int x, int y, int w, int h, int r) {
    GraphicsPath path;
    if (r<1) { SolidBrush br(c); g.FillRectangle(&br, x, y, w, h); return; }
    int d=r*2;
    path.AddArc(x,y,d,d,180,90); path.AddArc(x+w-d,y,d,d,270,90);
    path.AddArc(x+w-d,y+h-d,d,d,0,90); path.AddArc(x,y+h-d,d,d,90,90);
    path.CloseFigure();
    SolidBrush br(c); g.FillPath(&br, &path);
}
static void StrokeRR(Graphics& g, const Color& c, int x, int y, int w, int h, int r) {
    GraphicsPath path; int d=r*2;
    path.AddArc(x,y,d,d,180,90); path.AddArc(x+w-d,y,d,d,270,90);
    path.AddArc(x+w-d,y+h-d,d,d,0,90); path.AddArc(x,y+h-d,d,d,90,90);
    path.CloseFigure();
    Pen pen(c,1); g.DrawPath(&pen, &path);
}
static RectF DrawTxt(Graphics& g, const wchar_t* s, float sz, const Color& c, float x, float y,
                     float w=0, int align=0, bool bold=false) {
    FontFamily ff(L"Segoe UI");
    Font font(&ff, sz, bold?FontStyleBold:FontStyleRegular, UnitPixel);
    SolidBrush br(c);
    StringFormat sf; sf.SetTrimming(StringTrimmingEllipsisCharacter);
    if (align==1) sf.SetAlignment(StringAlignmentCenter);
    if (align==2) sf.SetAlignment(StringAlignmentFar);
    RectF lay(x, y, w>0?w:9999.f, sz*2.f), out;
    g.MeasureString(s,-1,&font,lay,&sf,&out);
    g.DrawString(s,-1,&font,lay,&sf,&br);
    return out;
}

static bool InRect(POINT p, RECT r) { return p.x>=r.left&&p.x<r.right&&p.y>=r.top&&p.y<r.bottom; }
static RECT MkRect(int x,int y,int w,int h) { return {x,y,x+w,y+h}; }

// ======================== PAINT ========================
static void PaintAll(Graphics& gfx, int W, int H) {
    gfx.SetSmoothingMode(SmoothingModeAntiAlias);
    gfx.SetTextRenderingHint(TextRenderingHintClearTypeGridFit);

    // background
    SolidBrush bgBr(C_BG); gfx.FillRectangle(&bgBr, 0, 0, W, H);

    // ---- title bar ----
    FillRR(gfx, C_SURF, 0, 0, W, TITLE_H, 0);
    DrawTxt(gfx, L"StringsChecker", 15, C_ACC, 16, 11, 0, 0, true);

    // close btn
    POINT curPt; GetCursorPos(&curPt); ScreenToClient(g.hwnd,&curPt);
    int bx = W-42, by=5, bsz=32;
    g.btnClose = MkRect(bx,by,bsz,bsz);
    if(InRect(curPt,g.btnClose)) FillRR(gfx,C_RED,bx,by,bsz,bsz,6);
    {Pen xp(C_TXT,1.6f);xp.SetStartCap(LineCapRound);xp.SetEndCap(LineCapRound);
     float cx=(float)bx+bsz/2.f,cy2=(float)by+bsz/2.f;
     gfx.DrawLine(&xp,cx-5,cy2-5,cx+5,cy2+5);gfx.DrawLine(&xp,cx+5,cy2-5,cx-5,cy2+5);}
    // min btn
    bx -= 36; g.btnMin = MkRect(bx,by,bsz,bsz);
    if(InRect(curPt,g.btnMin)) FillRR(gfx,C_SURF2,bx,by,bsz,bsz,6);
    {Pen mp(C_TXT,1.6f);mp.SetStartCap(LineCapRound);mp.SetEndCap(LineCapRound);
     float cx=(float)bx+bsz/2.f,cy2=(float)by+bsz/2.f;
     gfx.DrawLine(&mp,cx-5,cy2,cx+5,cy2);}

    Pen sepPen(C_BORD,1); gfx.DrawLine(&sepPen, 0, TITLE_H, W, TITLE_H);

    int cy = TITLE_H + 14;
    int pad = 20;

    // pre-build visible results list (needed before goto)
    std::vector<int> visIdx;
    for (int i=0; i<(int)g.results.size(); i++)
        if (g.results[i].found > 0) visIdx.push_back(i);

#ifndef NO_SERVER
    // ---- history banner ----
    if (g.hasHistory && !g.showHistory) {
        FillRR(gfx, Color(255,28,56,93), pad, cy, W-pad*2, 34, 8);
        DrawTxt(gfx, L"Это устройство уже проверялось", 13, C_ACC2, (float)pad+14, (float)cy+8);
        g.btnHistToggle = MkRect(W-pad-160, cy+2, 150, 30);
        DrawTxt(gfx, L"[История]", 13, C_ACC, (float)(W-pad-145), (float)cy+8);
        cy += 42;
    } else {
        g.btnHistToggle = {0,0,0,0};
    }

    // ---- history view ----
    if (g.showHistory) {
        DrawTxt(gfx, L"История проверок", 16, C_TXT, (float)pad, (float)cy, 0, 0, true);
        g.btnHistToggle = MkRect(W-pad-100, cy, 90, 26);
        FillRR(gfx, C_SURF2, W-pad-100, cy, 90, 26, 6);
        DrawTxt(gfx, L"Назад", 13, C_TXT2, (float)(W-pad-90), (float)cy+4);
        cy += 34;
        g.histRects.clear();
        for (int hi=0; hi<(int)g.history.size(); hi++) {
            auto& hc = g.history[hi];
            bool hexp = (g.expandedHist == hi);
            int detCount = 0;
            for (auto& r : hc.results) if (r.found>0) detCount++;
            int itemH = 32;
            if (hexp) itemH += 6 + (int)hc.results.size() * 24;

            FillRR(gfx, C_SURF, pad, cy, W-pad*2, itemH, 8);
            StrokeRR(gfx, C_BORD, pad, cy, W-pad*2, itemH, 8);

            const wchar_t* arrow = hexp ? L"▼" : L"▶";
            DrawTxt(gfx, arrow, 11, C_TXT2, (float)pad+10, (float)cy+8);
            DrawTxt(gfx, toW(hc.timestamp).c_str(), 13, C_TXT, (float)pad+30, (float)cy+7);

            std::wstring badge = std::to_wstring(detCount) + L" детект(ов)";
            Color bc = detCount > 0 ? C_RED : C_GRN;
            DrawTxt(gfx, badge.c_str(), 12, bc, (float)(W-pad-130), (float)cy+8);

            if (hexp) {
                int ey = cy + 34;
                for (auto& r : hc.results) {
                    Color rc = r.found > 0 ? C_RED : C_GRN;
                    std::string line = r.name + "  " + r.process;
                    DrawTxt(gfx, toW(line).c_str(), 12, C_TXT2, (float)pad+34, (float)ey);
                    std::wstring cnt = std::to_wstring(r.found) + L"/" + std::to_wstring(r.total);
                    DrawTxt(gfx, cnt.c_str(), 12, rc, (float)(W-pad-80), (float)ey, 60, 2);
                    ey += 24;
                }
            }
            g.histRects.push_back(MkRect(pad, cy, W-pad*2, itemH));
            cy += itemH + 6;
            if (cy > H-60) break;
        }
        goto footer;
    }
#endif // NO_SERVER

    // ---- sources ----
#ifdef NO_SERVER
    FillRR(gfx, C_SURF, pad, cy, W-pad*2, 60, 10);
    StrokeRR(gfx, C_BORD, pad, cy, W-pad*2, 60, 10);
    DrawTxt(gfx, L"Файл детектов", 14, C_TXT, (float)pad+14, (float)cy+8, 0, 0, true);
    { // local file
        DrawTxt(gfx, L"Файл:", 13, C_TXT2, (float)pad+14, (float)cy+32);
#else
    FillRR(gfx, C_SURF, pad, cy, W-pad*2, 88, 10);
    StrokeRR(gfx, C_BORD, pad, cy, W-pad*2, 88, 10);
    DrawTxt(gfx, L"Источники", 14, C_TXT, (float)pad+14, (float)cy+8, 0, 0, true);

    { // server status
        const wchar_t* st = g.serverChecked ? (g.serverOnline ? L"Онлайн" : L"Оффлайн") : L"...";
        Color sc = g.serverOnline ? C_GRN : C_RED;
        if (!g.serverChecked) sc = C_YEL;
        DrawTxt(gfx, L"Сервер:", 13, C_TXT2, (float)pad+14, (float)cy+32);
        DrawTxt(gfx, st, 13, sc, (float)pad+90, (float)cy+32);
        if (g.serverOnline) {
            std::wstring cnt = std::to_wstring(g.serverRules.size()) + L" детект(ов)";
            DrawTxt(gfx, cnt.c_str(), 12, C_TXT2, (float)pad+200, (float)cy+33);
        }
    }
    { // local file
        DrawTxt(gfx, L"Локальный:", 13, C_TXT2, (float)pad+14, (float)cy+56);
#endif
        {
#ifdef NO_SERVER
        int ly = cy + 32;
#else
        int ly = cy + 56;
#endif
        if (g.localPath.empty()) {
            DrawTxt(gfx, L"не загружен", 13, C_TXT2, (float)pad+110, (float)ly);
        } else {
            std::wstring lp = toW(g.localPath);
            if (lp.size()>45) lp = L"..."+lp.substr(lp.size()-42);
            DrawTxt(gfx, lp.c_str(), 12, C_TXT, (float)pad+110, (float)ly, (float)(W-pad*2-260));
            std::wstring cnt = std::to_wstring(g.localRules.size()) + L" детект(ов)";
            DrawTxt(gfx, cnt.c_str(), 12, C_TXT2, (float)(W-pad-170), (float)ly);
        }
        int bbx = W-pad-72, bby=ly-6;
        g.btnBrowse = MkRect(bbx, bby, 60, 28);
        FillRR(gfx, C_SURF2, bbx, bby, 60, 28, 6);
        StrokeRR(gfx, C_BORD, bbx, bby, 60, 28, 6);
        DrawTxt(gfx, L"Обзор", 12, C_TXT, (float)bbx+8, (float)bby+5);
        }
    }
#ifdef NO_SERVER
    cy += 72;
#else
    cy += 100;
#endif

    // ---- scan buttons ----
    {
        bool busy = g.scanning.load();
        int mode = g.scanMode;
#ifdef NO_SERVER
        // single scan button
        int bw = 260, bh = 36;
        int x0 = (W - bw) / 2;
        bool locBusy = busy;
        bool locReady = !busy && !g.localRules.empty();
        Color locC = locBusy ? Color(255,28,90,40) : (locReady ? Color(255,35,134,54) : C_SURF2);
        g.btnScanLocal = MkRect(x0, cy, bw, bh);
        FillRR(gfx, locC, x0, cy, bw, bh, 10);
        Color locTx = (locC.GetValue()==C_SURF2.GetValue()) ? C_TXT2 : Color(255,255,255,255);
        const wchar_t* locLbl = locBusy ? L"Сканирование..." : L"СКАНИРОВАТЬ";
        DrawTxt(gfx, locLbl, 13, locTx, (float)x0, (float)cy+9, (float)bw, 1, true);
#else
        int gap = 16, bw = 200, bh = 36;
        int totalW = bw*2 + gap;
        int x0 = (W - totalW) / 2;

        // Server scan button
        bool srvBusy = busy && mode == 1;
        bool srvReady = !busy && g.serverOnline && !g.serverRules.empty();
        Color srvC = srvBusy ? Color(255,50,100,180) : (srvReady ? C_ACC : C_SURF2);
        g.btnScanSrv = MkRect(x0, cy, bw, bh);
        FillRR(gfx, srvC, x0, cy, bw, bh, 10);
        Color srvTx = (srvC.GetValue()==C_SURF2.GetValue()) ? C_TXT2 : Color(255,13,17,23);
        const wchar_t* srvLbl = srvBusy ? L"Сканирование..." : L"Сервер";
        DrawTxt(gfx, srvLbl, 13, srvTx, (float)x0, (float)cy+9, (float)bw, 1, true);

        // Local scan button
        bool locBusy = busy && mode == 2;
        bool locReady = !busy && !g.localRules.empty();
        Color locC = locBusy ? Color(255,28,90,40) : (locReady ? Color(255,35,134,54) : C_SURF2);
        int x1 = x0 + bw + gap;
        g.btnScanLocal = MkRect(x1, cy, bw, bh);
        FillRR(gfx, locC, x1, cy, bw, bh, 10);
        Color locTx = (locC.GetValue()==C_SURF2.GetValue()) ? C_TXT2 : Color(255,255,255,255);
        const wchar_t* locLbl = locBusy ? L"Сканирование..." : L"Локальный";
        DrawTxt(gfx, locLbl, 13, locTx, (float)x1, (float)cy+9, (float)bw, 1, true);
#endif
    }
    cy += 46;

    // ---- progress ----
    if (g.scanning.load()) {
        // spinning circle
        float cx2 = (float)W/2, cy2 = (float)cy+20;
        Pen bgPen(C_SURF2, 3); gfx.DrawEllipse(&bgPen, cx2-15, cy2-15, 30.f, 30.f);
        Pen fgPen(C_ACC, 3); fgPen.SetStartCap(LineCapRound); fgPen.SetEndCap(LineCapRound);
        gfx.DrawArc(&fgPen, cx2-15, cy2-15, 30.f, 30.f, g.spinAngle, 90);
        // status text
        std::lock_guard<std::mutex> lk(g.statusMx);
        DrawTxt(gfx, toW(g.scanStatus).c_str(), 12, C_TXT2, (float)pad, (float)cy+42, (float)(W-pad*2), 1);
        cy += 64;
    } else if (!g.results.empty()) {
        gfx.DrawLine(&sepPen, pad, cy, W-pad, cy);
        cy += 8;
        if (visIdx.empty()) {
            DrawTxt(gfx, L"Ничего не обнаружено", 14, C_GRN, (float)pad, (float)cy+8, (float)(W-pad*2), 1);
            cy += 36;
        }
    }

    // ---- results (only show detects with found > 0) ----
    if (!visIdx.empty()) {
        std::wstring hdr = L"Результаты (" + std::to_wstring(visIdx.size()) + L")";
        DrawTxt(gfx, hdr.c_str(), 14, C_TXT, (float)pad, (float)cy, 0, 0, true);
        cy += 24;

        int resTop = cy;
        int resBot = H - 40;
        Region oldClip; gfx.GetClip(&oldClip);
        gfx.SetClip(Rect(0, resTop, W, resBot-resTop));

        g.resultRects.clear();
        g.resultMap.clear();
        int ry = resTop - g.scrollY;

        for (int vi=0; vi<(int)visIdx.size(); vi++) {
            int i = visIdx[vi];
            auto& r = g.results[i];
            bool expanded = (g.expandedIdx==i);
            bool hasStrings = expanded && r.showStrings && !r.foundStrings.empty();
            bool hiddenNote = expanded && !r.showStrings;
            int itemH = 56;
            if (hasStrings) itemH += 4 + (int)r.foundStrings.size()*22;
            else if (hiddenNote) itemH += 26;

            if (ry+itemH > resTop-100 && ry < resBot+100) {
                Color cardBg = r.found>0 ? Color(255,30,20,20) : C_SURF;
                FillRR(gfx, cardBg, pad, ry, W-pad*2, itemH, 8);
                StrokeRR(gfx, r.found>0?Color(255,80,40,40):C_BORD, pad, ry, W-pad*2, itemH, 8);

                // arrow
                const wchar_t* arrow = expanded ? L"▼" : L"▶";
                DrawTxt(gfx, arrow, 11, C_TXT2, (float)pad+10, (float)ry+8);

                // name
                DrawTxt(gfx, toW(r.name).c_str(), 14, C_TXT, (float)pad+30, (float)ry+6, 0, 0, true);

                // process + pid + window title
                std::string proc_info = r.process;
                if (r.pid) {
                    proc_info += " (PID: "+std::to_string(r.pid)+")";
                    if (!r.windowTitle.empty()) proc_info += "  "+r.windowTitle;
                } else {
                    proc_info += u8" — не найден";
                }
                DrawTxt(gfx, toW(proc_info).c_str(), 12, C_TXT2, (float)pad+30, (float)ry+28, (float)(W-pad*2-120));

                // count
                std::wstring cnt = std::to_wstring(r.found)+L"/"+std::to_wstring(r.total);
                Color cntC = r.found>0 ? C_RED : C_GRN;
                DrawTxt(gfx, cnt.c_str(), 15, cntC, (float)(W-pad-80), (float)ry+8, 60, 2, true);

                // source badge
                const wchar_t* badge = r.isServer ? L"SRV" : L"LOCAL";
                Color badgeC = r.isServer ? Color(255,40,60,100) : Color(255,60,60,40);
                FillRR(gfx, badgeC, W-pad-60, ry+32, 46, 18, 4);
                DrawTxt(gfx, badge, 10, C_TXT2, (float)(W-pad-58), (float)ry+34);

                // expanded content
                if (hasStrings) {
                    int sy2 = ry+56;
                    for (auto& fs : r.foundStrings) {
                        DrawTxt(gfx, L"•", 12, C_ACC, (float)pad+34, (float)sy2);
                        std::wstring ws = toW(fs);
                        if (ws.size()>80) ws = ws.substr(0,77)+L"...";
                        DrawTxt(gfx, ws.c_str(), 12, C_TXT, (float)pad+50, (float)sy2, (float)(W-pad*2-80));
                        sy2 += 22;
                    }
                } else if (hiddenNote) {
                    DrawTxt(gfx, L"Для этого детекта отображение строк скрыто", 12, C_TXT2, (float)pad+34, (float)ry+58);
                }

                g.resultRects.push_back(MkRect(pad, ry, W-pad*2, itemH));
                g.resultMap.push_back(i);
            } else {
                g.resultRects.push_back(MkRect(pad, ry, W-pad*2, itemH));
                g.resultMap.push_back(i);
            }
            ry += itemH + 6;
        }
        g.maxScroll = (std::max)(0, ry + g.scrollY - resBot + 8);
        gfx.SetClip(&oldClip);
    }

footer:
    // ---- footer ----
    int fy = H - 32;
    gfx.DrawLine(&sepPen, 0, fy-2, W, fy-2);
    g.btnCredit = MkRect(pad, fy, 200, 22);
    DrawTxt(gfx, L"by edoooss22", 12, C_ACC, (float)pad, (float)fy+2);
#ifndef NO_SERVER
    DrawTxt(gfx, L"HWID: ", 11, C_TXT2, (float)(W-pad-260), (float)fy+3);
    DrawTxt(gfx, toW(g.hwid).c_str(), 11, C_TXT2, (float)(W-pad-220), (float)fy+3);
#else
    DrawTxt(gfx, L"Offline", 11, C_TXT2, (float)(W-pad-80), (float)fy+3);
#endif
}

// ======================== WNDPROC ========================
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        SetTimer(hwnd, 1, 30, nullptr);
        return 0;
    case WM_TIMER:
        if (wParam==1) {
            if (g.scanning.load()) { g.spinAngle+=8; if(g.spinAngle>=360)g.spinAngle-=360; InvalidateRect(hwnd,nullptr,FALSE); }
        }
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);
        HDC mem = CreateCompatibleDC(hdc);
        HBITMAP bmp = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
        HBITMAP old = (HBITMAP)SelectObject(mem, bmp);
        { Graphics gfx(mem); PaintAll(gfx, rc.right, rc.bottom); }
        BitBlt(hdc, 0,0, rc.right, rc.bottom, mem, 0,0, SRCCOPY);
        SelectObject(mem, old); DeleteObject(bmp); DeleteDC(mem);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND: return 1;
    case WM_LBUTTONDOWN: {
        POINT pt = {(short)LOWORD(lParam), (short)HIWORD(lParam)};
        if (InRect(pt, g.btnClose)) { PostQuitMessage(0); return 0; }
        if (InRect(pt, g.btnMin)) { ShowWindow(hwnd, SW_MINIMIZE); return 0; }
        if (InRect(pt, g.btnCredit)) {
            ShellExecuteA(nullptr,"open","https://discord.com/users/506496308631306250",nullptr,nullptr,SW_SHOWNORMAL);
            return 0;
        }
#ifndef NO_SERVER
        if (InRect(pt, g.btnHistToggle)) {
            g.showHistory = !g.showHistory;
            InvalidateRect(hwnd,nullptr,FALSE);
            return 0;
        }
#endif
        if (InRect(pt, g.btnBrowse) && !g.scanning.load()) {
            wchar_t path[MAX_PATH]={};
            OPENFILENAMEW ofn={}; ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=hwnd;
            ofn.lpstrFilter=L"JSON\0*.json\0All\0*.*\0";
            ofn.lpstrFile=path; ofn.nMaxFile=MAX_PATH; ofn.Flags=OFN_FILEMUSTEXIST;
            if (GetOpenFileNameW(&ofn)) {
                g.localPath = toU8(path);
                std::string json = readFile(g.localPath);
                g.localRules = loadDetects(json, false);
                InvalidateRect(hwnd,nullptr,FALSE);
            }
            return 0;
        }
#ifndef NO_SERVER
        if (InRect(pt, g.btnScanSrv) && !g.scanning.load() && g.serverOnline && !g.serverRules.empty()) {
            g.scanMode = 1; g.scanning = true; g.scanPct = 0; g.spinAngle = 0;
            InvalidateRect(hwnd,nullptr,FALSE);
            std::thread(doScan).detach();
            return 0;
        }
#endif
        if (InRect(pt, g.btnScanLocal) && !g.scanning.load() && !g.localRules.empty()) {
            g.scanMode = 2; g.scanning = true; g.scanPct = 0; g.spinAngle = 0;
            InvalidateRect(hwnd,nullptr,FALSE);
            std::thread(doScan).detach();
            return 0;
        }
        // result click
        for (int i=0; i<(int)g.resultRects.size(); i++) {
            if (InRect(pt, g.resultRects[i])) {
                int ri = (i < (int)g.resultMap.size()) ? g.resultMap[i] : i;
                g.expandedIdx = (g.expandedIdx==ri) ? -1 : ri;
                InvalidateRect(hwnd,nullptr,FALSE);
                return 0;
            }
        }
#ifndef NO_SERVER
        // history click
        for (int i=0; i<(int)g.histRects.size(); i++) {
            if (InRect(pt, g.histRects[i])) {
                g.expandedHist = (g.expandedHist==i) ? -1 : i;
                InvalidateRect(hwnd,nullptr,FALSE);
                return 0;
            }
        }
#endif
        // title bar drag
        if (pt.y < TITLE_H) {
            ReleaseCapture();
            SendMessage(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
            return 0;
        }
        return 0;
    }
    case WM_MOUSEMOVE:
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    case WM_MOUSEWHEEL: {
        int delta = GET_WHEEL_DELTA_WPARAM(wParam);
        g.scrollY -= delta/3;
        if (g.scrollY<0) g.scrollY=0;
        if (g.scrollY>g.maxScroll) g.scrollY=g.maxScroll;
        InvalidateRect(hwnd,nullptr,FALSE);
        return 0;
    }
    case WM_SETCURSOR: {
        POINT pt; GetCursorPos(&pt); ScreenToClient(hwnd, &pt);
        bool hand = InRect(pt,g.btnScanLocal)||InRect(pt,g.btnBrowse)||
                    InRect(pt,g.btnClose)||InRect(pt,g.btnMin)||InRect(pt,g.btnCredit);
#ifndef NO_SERVER
        hand = hand||InRect(pt,g.btnScanSrv)||InRect(pt,g.btnHistToggle);
        if (!hand) for (auto& r:g.histRects) if(InRect(pt,r)){hand=true;break;}
#endif
        if (!hand) for (auto& r:g.resultRects) if(InRect(pt,r)){hand=true;break;}
        SetCursor(hand ? g.curHand : g.curArrow);
        return TRUE;
    }
    case WM_SCAN_DONE:
        InvalidateRect(hwnd,nullptr,FALSE);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0); return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// ======================== WINMAIN ========================
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int) {
    SetProcessDPIAware();
#ifndef NO_SERVER
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    ULONG_PTR gdipTok;
    GdiplusStartupInput gdipIn;
    GdiplusStartup(&gdipTok, &gdipIn, nullptr);

    g.curHand = LoadCursor(nullptr, IDC_HAND);
    g.curArrow = LoadCursor(nullptr, IDC_ARROW);
#ifndef NO_SERVER
    g.hwid = getHWID();
#endif

    std::string dir = getExeDir();
#ifndef NO_SERVER
    // load config
    std::string cfgJson = readFile(dir+"config.json");
    if (!cfgJson.empty()) {
        JVal cfg = jparse(cfgJson);
        if (cfg["server_host"].type == JVal::STR) {
            std::string h = cfg["server_host"].s;
            if (h.rfind("https://",0)==0) { g.serverHttps=true; h=h.substr(8); }
            else if (h.rfind("http://",0)==0) { h=h.substr(7); }
            while (!h.empty() && h.back()=='/') h.pop_back();
            g.serverHost = h;
        }
        if (cfg["server_port"].type == JVal::NUM) g.serverPort = (int)cfg["server_port"].n;
        if (cfg["server_path"].type == JVal::STR) g.serverBasePath = cfg["server_path"].s;
    }
#endif

    // auto-load detects.json from exe dir
    std::string autoDetects = readFile(dir+"detects.json");
    if (!autoDetects.empty()) {
        g.localPath = dir+"detects.json";
        g.localRules = loadDetects(autoDetects, false);
    }

    // register window class
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_DROPSHADOW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = g.curArrow;
    wc.lpszClassName = L"StringsCheckerWnd";
    wc.hIcon = LoadIcon(nullptr, IDI_SHIELD);
    RegisterClassExW(&wc);

    int sx = GetSystemMetrics(SM_CXSCREEN), sy = GetSystemMetrics(SM_CYSCREEN);
    g.hwnd = CreateWindowExW(WS_EX_APPWINDOW, wc.lpszClassName, L"StringsChecker",
                             WS_POPUP | WS_MINIMIZEBOX,
                             (sx-W_W)/2, (sy-W_H)/2, W_W, W_H,
                             nullptr, nullptr, hInst, nullptr);
    ShowWindow(g.hwnd, SW_SHOW);
    UpdateWindow(g.hwnd);

#ifndef NO_SERVER
    // background: check server + load history
    std::thread([&]{
        std::string resp = srvGet("/ping");
        g.serverOnline = !resp.empty() && resp.find("online")!=std::string::npos;
        g.serverChecked = true;
        if (g.serverOnline) {
            std::string dj = srvGet("/detects");
            if (!dj.empty()) g.serverRules = loadDetects(dj, true);
            std::string hj = srvGet("/history/"+g.hwid);
            if (!hj.empty()) {
                JVal root = jparse(hj);
                for (auto& c : root["checks"].a) {
                    HistoryCheck hc;
                    hc.timestamp = c["timestamp"].s;
                    for (auto& r : c["results"].a) {
                        DetectResult dr;
                        dr.name = r["name"].s; dr.process = r["process"].s;
                        dr.pid = (DWORD)r["pid"].n; dr.found = (int)r["found"].n;
                        dr.total = (int)r["total"].n; dr.isServer = true;
                        hc.results.push_back(dr);
                    }
                    g.history.push_back(hc);
                }
                if (!g.history.empty()) g.hasHistory = true;
            }
        }
        InvalidateRect(g.hwnd, nullptr, FALSE);
    }).detach();
#endif

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    GdiplusShutdown(gdipTok);
#ifndef NO_SERVER
    WSACleanup();
#endif
    return 0;
}
