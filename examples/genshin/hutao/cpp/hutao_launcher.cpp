#include <windows.h>
#include <commctrl.h>
#include <string>
#include <sstream>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")

// Control IDs
#define ID_EDIT_GAME_PATH       1001
#define ID_EDIT_FPS             1002
#define ID_EDIT_FOV             1003
#define ID_CHECK_ENABLE_FPS     1004
#define ID_CHECK_ENABLE_FOV     1005
#define ID_CHECK_DISABLE_FOG    1006
#define ID_CHECK_FIX_LOW_FOV    1007
#define ID_CHECK_HIDE_BANNER    1008
#define ID_CHECK_REMOVE_TEAM    1009
#define ID_CHECK_DISABLE_CAMERA 1010
#define ID_CHECK_HIDE_DAMAGE    1011
#define ID_CHECK_TOUCH_SCREEN   1012
#define ID_CHECK_REDIRECT_CRAFT 1013
#define ID_BUTTON_LAUNCH        1014
#define ID_BUTTON_EXIT          1015
#define ID_BUTTON_ABOUT         1016
#define ID_BUTTON_APPLY         1017
#define ID_BUTTON_RESET         1018
#define ID_STATIC_REMINDER      1019

// Structures matching the injector
struct FunctionOffsets {
    uint32_t MickeyWonder;
    uint32_t MickeyWonderPartner;
    uint32_t MickeyWonderPartner2;
    uint32_t SetFieldOfView;
    uint32_t SetEnableFogRendering;
    uint32_t SetTargetFrameRate;
    uint32_t OpenTeam;
    uint32_t OpenTeamPageAccordingly;
    uint32_t CheckCanEnter;
    uint32_t SetupQuestBanner;
    uint32_t FindGameObject;
    uint32_t SetActive;
    uint32_t EventCameraMove;
    uint32_t ShowOneDamageTextEx;
    uint32_t SwitchInputDeviceToTouchScreen;
    uint32_t MickeyWonderCombineEntry;
    uint32_t MickeyWonderCombineEntryPartner;
};

enum class IslandState : int {
    None = 0,
    Error = 1,
    Started = 2,
    Stopped = 3,
};

struct IslandEnvironment {
    IslandState State;
    DWORD LastError;
    FunctionOffsets FunctionOffsets;
    BOOL EnableSetFieldOfView;
    FLOAT FieldOfView;
    BOOL FixLowFovScene;
    BOOL DisableFog;
    BOOL EnableSetTargetFrameRate;
    INT32 TargetFrameRate;
    BOOL RemoveOpenTeamProgress;
    BOOL HideQuestBanner;
    BOOL DisableEventCameraMove;
    BOOL DisableShowDamageText;
    BOOL UsingTouchScreen;
    BOOL RedirectCombineEntry;
};

// Global variables
HWND g_hMainWnd = NULL;
HANDLE g_hMemoryMappedFile = NULL;
LPVOID g_pSharedMemory = NULL;
HANDLE g_hProcess = NULL;
DWORD g_processId = 0;

static constexpr LPCSTR SHARED_MEMORY_NAME = "4F3E8543-40F7-4808-82DC-21E48A6037A7";
static constexpr FunctionOffsets ChineseOffsets = {
    87242192, 4830752, 215314944, 17204528, 277807600, 277729120,
    118414576, 118384496, 156982512, 124927536, 277741040, 277740368,
    186643424, 204578400, 144617776, 127845632, 201143472
};

// Function declarations
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
void CreateControls(HWND hwnd);
void LaunchGame();
void ApplySettings();
void ResetSettings();
void ShowAbout();
bool CheckAdminRights();
bool CreateSharedMemory();
void ConfigureEnvironment();
bool LaunchGameProcess(const std::string& gamePath);
bool InjectDLL();
bool WaitForMainModule(const std::string& exeName);
bool GetMainModuleInfo(const std::string& exeName);
DWORD GetMainThreadId(DWORD processId);
void Cleanup();
bool ValidateFPS(const std::string& text, int& outValue);
bool ValidateFOV(const std::string& text, float& outValue);

// Utility functions
std::string GetWindowText(HWND hwnd) {
    int len = GetWindowTextLength(hwnd);
    if (len == 0) return "";
    
    std::string result(len, 0);
    GetWindowTextA(hwnd, &result[0], len + 1);
    return result;
}

// Enhanced validation functions
bool ValidateFPS(const std::string& text, int& outValue) {
    if (text.empty()) return false;
    
    std::istringstream iss(text);
    iss >> outValue;
    
    // Check if conversion succeeded and entire string was consumed
    return !iss.fail() && iss.eof() && outValue >= 30;
}

bool ValidateFOV(const std::string& text, float& outValue) {
    if (text.empty()) return false;
    
    std::istringstream iss(text);
    iss >> outValue;
    
    // Check if conversion succeeded and entire string was consumed
    return !iss.fail() && iss.eof() && outValue >= 1.0f;
}

// Check administrator rights
bool CheckAdminRights() {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                &administratorsGroup)) {
        CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
        FreeSid(administratorsGroup);
    }
    
    return isAdmin == TRUE;
}

// Main window procedure
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        CreateControls(hwnd);
        break;
        
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_BUTTON_LAUNCH:
            LaunchGame();
            break;
        case ID_BUTTON_APPLY:
            ApplySettings();
            break;
        case ID_BUTTON_RESET:
            ResetSettings();
            break;
        case ID_BUTTON_ABOUT:
            ShowAbout();
            break;
        case ID_BUTTON_EXIT:
            PostQuitMessage(0);
            break;
        }
        break;
        
    case WM_CLOSE:
        Cleanup();
        PostQuitMessage(0);
        break;
        
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// Create all controls
void CreateControls(HWND hwnd) {
    int y = 10;
    int lineHeight = 30;
    int checkBoxHeight = 25;
    
    // Game path
    CreateWindow("STATIC", "Game Path:", WS_VISIBLE | WS_CHILD,
        10, y, 100, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
    CreateWindow("EDIT", "D:\\Program Files\\Genshin Impact\\Genshin Impact Game\\YuanShen.exe",
        WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
        120, y, 450, 22, hwnd, (HMENU)ID_EDIT_GAME_PATH, GetModuleHandle(NULL), NULL);
    y += lineHeight;
    
    // FPS settings
    CreateWindow("STATIC", "Target FPS:", WS_VISIBLE | WS_CHILD,
        10, y, 80, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
    CreateWindow("EDIT", "60", WS_VISIBLE | WS_CHILD | WS_BORDER,
        100, y, 60, 22, hwnd, (HMENU)ID_EDIT_FPS, GetModuleHandle(NULL), NULL);
    CreateWindow("BUTTON", "Enable FPS", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        170, y, 100, checkBoxHeight, hwnd, (HMENU)ID_CHECK_ENABLE_FPS, GetModuleHandle(NULL), NULL);
    y += lineHeight;
    
    // FOV settings
    CreateWindow("STATIC", "Field of View:", WS_VISIBLE | WS_CHILD,
        10, y, 90, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
    CreateWindow("EDIT", "45.0", WS_VISIBLE | WS_CHILD | WS_BORDER,
        110, y, 60, 22, hwnd, (HMENU)ID_EDIT_FOV, GetModuleHandle(NULL), NULL); 
    CreateWindow("BUTTON", "Enable FOV", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        180, y, 100, checkBoxHeight, hwnd, (HMENU)ID_CHECK_ENABLE_FOV, GetModuleHandle(NULL), NULL);
    y += lineHeight;
    
    // Checkboxes
    CreateWindow("BUTTON", "Fix Low FOV Scenes", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        10, y, 150, checkBoxHeight, hwnd, (HMENU)ID_CHECK_FIX_LOW_FOV, GetModuleHandle(NULL), NULL);
    CreateWindow("BUTTON", "Disable Fog", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        170, y, 100, checkBoxHeight, hwnd, (HMENU)ID_CHECK_DISABLE_FOG, GetModuleHandle(NULL), NULL);
    y += lineHeight;
    
    CreateWindow("BUTTON", "Hide Quest Banner", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        10, y, 150, checkBoxHeight, hwnd, (HMENU)ID_CHECK_HIDE_BANNER, GetModuleHandle(NULL), NULL);
    CreateWindow("BUTTON", "Remove Team Animation", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        170, y, 170, checkBoxHeight, hwnd, (HMENU)ID_CHECK_REMOVE_TEAM, GetModuleHandle(NULL), NULL);
    y += lineHeight;
    
    CreateWindow("BUTTON", "Disable Event Camera", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        10, y, 150, checkBoxHeight, hwnd, (HMENU)ID_CHECK_DISABLE_CAMERA, GetModuleHandle(NULL), NULL);
    CreateWindow("BUTTON", "Hide Damage Numbers", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        170, y, 170, checkBoxHeight, hwnd, (HMENU)ID_CHECK_HIDE_DAMAGE, GetModuleHandle(NULL), NULL);
    y += lineHeight;
    
    CreateWindow("BUTTON", "Touch Screen Mode", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        10, y, 150, checkBoxHeight, hwnd, (HMENU)ID_CHECK_TOUCH_SCREEN, GetModuleHandle(NULL), NULL);
    CreateWindow("BUTTON", "Redirect Crafting Table", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        170, y, 170, checkBoxHeight, hwnd, (HMENU)ID_CHECK_REDIRECT_CRAFT, GetModuleHandle(NULL), NULL);
    y += lineHeight + 10;
    
    // Add reminder text
    CreateWindow("STATIC", "NOTE: Remember to click Exit button to restore default settings", 
        WS_VISIBLE | WS_CHILD,
        10, y, 500, 15, hwnd, (HMENU)ID_STATIC_REMINDER, GetModuleHandle(NULL), NULL);
    y += 20;
    
    // Buttons
    CreateWindow("BUTTON", "Launch Game", WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        10, y, 100, 35, hwnd, (HMENU)ID_BUTTON_LAUNCH, GetModuleHandle(NULL), NULL);
    CreateWindow("BUTTON", "Apply", WS_VISIBLE | WS_CHILD,
        120, y, 60, 35, hwnd, (HMENU)ID_BUTTON_APPLY, GetModuleHandle(NULL), NULL);
    CreateWindow("BUTTON", "Reset", WS_VISIBLE | WS_CHILD,
        190, y, 60, 35, hwnd, (HMENU)ID_BUTTON_RESET, GetModuleHandle(NULL), NULL);
    CreateWindow("BUTTON", "About", WS_VISIBLE | WS_CHILD,
        260, y, 60, 35, hwnd, (HMENU)ID_BUTTON_ABOUT, GetModuleHandle(NULL), NULL);
    CreateWindow("BUTTON", "Exit", WS_VISIBLE | WS_CHILD,
        330, y, 60, 35, hwnd, (HMENU)ID_BUTTON_EXIT, GetModuleHandle(NULL), NULL);
    
    // Set default check states - enable FPS, FOV, and Fix Low FOV
    SendMessage(GetDlgItem(hwnd, ID_CHECK_ENABLE_FPS), BM_SETCHECK, BST_CHECKED, 0);
    SendMessage(GetDlgItem(hwnd, ID_CHECK_ENABLE_FOV), BM_SETCHECK, BST_CHECKED, 0);
    SendMessage(GetDlgItem(hwnd, ID_CHECK_FIX_LOW_FOV), BM_SETCHECK, BST_CHECKED, 0);
    
    // Initially disable Apply button
    EnableWindow(GetDlgItem(hwnd, ID_BUTTON_APPLY), FALSE);
}

// Launch game with current settings
void LaunchGame() {
    if (!CheckAdminRights()) {
        MessageBox(g_hMainWnd, "Administrator rights required for game injection!", "Permission Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::string gamePath = GetWindowText(GetDlgItem(g_hMainWnd, ID_EDIT_GAME_PATH));
    if (gamePath.empty()) {
        MessageBox(g_hMainWnd, "Please enter game path!", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    if (GetFileAttributesA(gamePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        MessageBox(g_hMainWnd, "Game file not found!", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    if (GetFileAttributes("hutao_minhook.dll") == INVALID_FILE_ATTRIBUTES) {
        MessageBox(g_hMainWnd, "hutao_minhook.dll not found!", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    // Validate FPS and FOV parameters
    std::string fpsText = GetWindowText(GetDlgItem(g_hMainWnd, ID_EDIT_FPS));
    std::string fovText = GetWindowText(GetDlgItem(g_hMainWnd, ID_EDIT_FOV));
    
    int fps;
    float fov;
    
    if (!ValidateFPS(fpsText, fps)) {
        MessageBox(g_hMainWnd, "FPS must be a positive integer >= 30!", "Invalid FPS", MB_OK | MB_ICONERROR);
        return;
    }
    
    if (!ValidateFOV(fovText, fov)) {
        MessageBox(g_hMainWnd, "FOV must be a number >= 1.0!", "Invalid FOV", MB_OK | MB_ICONERROR);
        return;
    }
    
    // Disable Launch button immediately to prevent multiple launches
    EnableWindow(GetDlgItem(g_hMainWnd, ID_BUTTON_LAUNCH), FALSE);
    
    if (!CreateSharedMemory()) {
        MessageBox(g_hMainWnd, "Failed to create shared memory!", "Error", MB_OK | MB_ICONERROR);
        EnableWindow(GetDlgItem(g_hMainWnd, ID_BUTTON_LAUNCH), TRUE);  // Re-enable on failure
        return;
    }
    
    ConfigureEnvironment();
    
    if (!LaunchGameProcess(gamePath)) {
        MessageBox(g_hMainWnd, "Failed to launch game!", "Error", MB_OK | MB_ICONERROR);
        EnableWindow(GetDlgItem(g_hMainWnd, ID_BUTTON_LAUNCH), TRUE);  // Re-enable on failure
        return;
    }
    
    if (!InjectDLL()) {
        MessageBox(g_hMainWnd, "Failed to inject DLL!", "Error", MB_OK | MB_ICONERROR);
        EnableWindow(GetDlgItem(g_hMainWnd, ID_BUTTON_LAUNCH), TRUE);  // Re-enable on failure
        return;
    }
    
    // Enable Apply button after successful launch
    EnableWindow(GetDlgItem(g_hMainWnd, ID_BUTTON_APPLY), TRUE);
}

// Apply current settings to running game
void ApplySettings() {
    if (!g_pSharedMemory) return;
    
    // Validate parameters before applying
    std::string fpsText = GetWindowText(GetDlgItem(g_hMainWnd, ID_EDIT_FPS));
    std::string fovText = GetWindowText(GetDlgItem(g_hMainWnd, ID_EDIT_FOV));
    
    int fps;
    float fov;
    
    if (!ValidateFPS(fpsText, fps)) {
        MessageBox(g_hMainWnd, "FPS must be a positive integer >= 30!", "Invalid FPS", MB_OK | MB_ICONERROR);
        return;
    }
    
    if (!ValidateFOV(fovText, fov)) {
        MessageBox(g_hMainWnd, "FOV must be a number >= 1.0!", "Invalid FOV", MB_OK | MB_ICONERROR);
        return;
    }
    
    ConfigureEnvironment();
}

// Reset settings to default values and apply immediately
void ResetSettings() {
    // Reset UI controls first
    SetWindowText(GetDlgItem(g_hMainWnd, ID_EDIT_FPS), "60");
    SetWindowText(GetDlgItem(g_hMainWnd, ID_EDIT_FOV), "45.0");
    SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_ENABLE_FPS), BM_SETCHECK, BST_CHECKED, 0);
    SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_ENABLE_FOV), BM_SETCHECK, BST_CHECKED, 0);
    SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_FIX_LOW_FOV), BM_SETCHECK, BST_CHECKED, 0);
    SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_DISABLE_FOG), BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_HIDE_BANNER), BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_REMOVE_TEAM), BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_DISABLE_CAMERA), BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_HIDE_DAMAGE), BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_TOUCH_SCREEN), BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_REDIRECT_CRAFT), BM_SETCHECK, BST_UNCHECKED, 0);
    
    // Apply the reset settings immediately if shared memory exists
    if (g_pSharedMemory) {
        ConfigureEnvironment();
    }
}

void ShowAbout() {
    std::string aboutText = 
        "Hutao Game Launcher v1.0\n\n"
        "A simple GUI launcher for Genshin Impact modifications\n"
        "Built with pure Win32 API for maximum compatibility\n\n"
        "Author: Yoimiya\n"
        "License: MIT\n"
        "Repository: https://github.com/Rukkhadevata123/min_hook_rs\n\n"
        "Based on min_hook_rs - A Rust implementation of MinHook\n"
        "for Windows x64 function hooking with enhanced precision\n\n"
        "@2025 - Licensed under the MIT License\n"
        "Permission is hereby granted, free of charge, to any person\n"
        "obtaining a copy of this software and associated documentation\n"
        "files, to deal in the Software without restriction.\n\n"
        "THIS SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND.";
    
    MessageBox(g_hMainWnd, aboutText.c_str(), "About Hutao Launcher", MB_OK | MB_ICONINFORMATION);
}

// Create shared memory
bool CreateSharedMemory() {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    g_hMemoryMappedFile = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        &sa,
        PAGE_READWRITE,
        0,
        sizeof(IslandEnvironment),
        SHARED_MEMORY_NAME
    );

    if (!g_hMemoryMappedFile) {
        return false;
    }

    g_pSharedMemory = MapViewOfFile(
        g_hMemoryMappedFile,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        sizeof(IslandEnvironment)
    );

    return g_pSharedMemory != NULL;
}

// Configure environment with current settings
void ConfigureEnvironment() {
    if (!g_pSharedMemory) return;

    IslandEnvironment* pEnv = static_cast<IslandEnvironment*>(g_pSharedMemory);
    ZeroMemory(pEnv, sizeof(IslandEnvironment));

    // Use validated values
    std::string fpsText = GetWindowText(GetDlgItem(g_hMainWnd, ID_EDIT_FPS));
    std::string fovText = GetWindowText(GetDlgItem(g_hMainWnd, ID_EDIT_FOV));
    
    int fps;
    float fov;
    ValidateFPS(fpsText, fps);
    ValidateFOV(fovText, fov);
    
    bool enableFps = SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_ENABLE_FPS), BM_GETCHECK, 0, 0) == BST_CHECKED;
    bool enableFov = SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_ENABLE_FOV), BM_GETCHECK, 0, 0) == BST_CHECKED;
    bool fixLowFov = SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_FIX_LOW_FOV), BM_GETCHECK, 0, 0) == BST_CHECKED;
    bool disableFog = SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_DISABLE_FOG), BM_GETCHECK, 0, 0) == BST_CHECKED;
    bool hideBanner = SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_HIDE_BANNER), BM_GETCHECK, 0, 0) == BST_CHECKED;
    bool removeTeam = SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_REMOVE_TEAM), BM_GETCHECK, 0, 0) == BST_CHECKED;
    bool disableCamera = SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_DISABLE_CAMERA), BM_GETCHECK, 0, 0) == BST_CHECKED;
    bool hideDamage = SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_HIDE_DAMAGE), BM_GETCHECK, 0, 0) == BST_CHECKED;
    bool touchScreen = SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_TOUCH_SCREEN), BM_GETCHECK, 0, 0) == BST_CHECKED;
    bool redirectCraft = SendMessage(GetDlgItem(g_hMainWnd, ID_CHECK_REDIRECT_CRAFT), BM_GETCHECK, 0, 0) == BST_CHECKED;

    pEnv->FunctionOffsets = ChineseOffsets;
    pEnv->EnableSetFieldOfView = enableFov ? TRUE : FALSE;
    pEnv->FieldOfView = fov;
    pEnv->FixLowFovScene = fixLowFov ? TRUE : FALSE;
    pEnv->DisableFog = disableFog ? TRUE : FALSE;
    pEnv->EnableSetTargetFrameRate = enableFps ? TRUE : FALSE;
    pEnv->TargetFrameRate = fps;
    pEnv->RemoveOpenTeamProgress = removeTeam ? TRUE : FALSE;
    pEnv->HideQuestBanner = hideBanner ? TRUE : FALSE;
    pEnv->DisableEventCameraMove = disableCamera ? TRUE : FALSE;
    pEnv->DisableShowDamageText = hideDamage ? TRUE : FALSE;
    pEnv->UsingTouchScreen = touchScreen ? TRUE : FALSE;
    pEnv->RedirectCombineEntry = redirectCraft ? TRUE : FALSE;
    pEnv->State = IslandState::Started;
}

// Launch game process
bool LaunchGameProcess(const std::string& gamePath) {
    std::string gameDir = gamePath.substr(0, gamePath.find_last_of("\\/"));
    
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    BOOL result = CreateProcessA(
        gamePath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        gameDir.c_str(),
        &si,
        &pi);
        
    if (!result) {
        return false;
    }

    CloseHandle(pi.hThread);
    g_hProcess = pi.hProcess;
    g_processId = pi.dwProcessId;

    SetPriorityClass(g_hProcess, HIGH_PRIORITY_CLASS);
    Sleep(10000);

    return WaitForMainModule("YuanShen.exe");
}

// Wait for main module to load
bool WaitForMainModule(const std::string& exeName) {
    int timeout = 300;
    while (timeout > 0) {
        if (GetMainModuleInfo(exeName)) {
            return true;
        }
        Sleep(100);
        timeout--;
    }
    return false;
}

// Check if main module is loaded
bool GetMainModuleInfo(const std::string& exeName) {
    if (!g_hProcess) return false;
    
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    if (!EnumProcessModules(g_hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return false;
    }

    DWORD moduleCount = cbNeeded / sizeof(HMODULE);
    
    for (DWORD i = 0; i < moduleCount; i++) {
        CHAR moduleName[MAX_PATH];
        if (GetModuleFileNameExA(g_hProcess, hMods[i], moduleName, sizeof(moduleName))) {
            std::string name = moduleName;
            size_t lastSlash = name.find_last_of("\\/");
            if (lastSlash != std::string::npos) {
                name = name.substr(lastSlash + 1);
            }

            if (name == exeName) {
                return true;
            }
        }
    }
    return false;
}

// Inject DLL using SetWindowsHookEx
bool InjectDLL() {
    HMODULE hDll = LoadLibraryA("hutao_minhook.dll");
    if (!hDll) {
        return false;
    }

    HOOKPROC hookProc = nullptr;
    auto pGetHook = (HRESULT(WINAPI*)(HOOKPROC*))GetProcAddress(hDll, "DllGetWindowsHookForHutao");
    if (!pGetHook) {
        pGetHook = (HRESULT(WINAPI*)(HOOKPROC*))GetProcAddress(hDll, "IslandGetWindowHook");
    }

    if (!pGetHook || FAILED(pGetHook(&hookProc))) {
        FreeLibrary(hDll);
        return false;
    }

    DWORD threadId = GetMainThreadId(g_processId);
    if (threadId == 0) {
        FreeLibrary(hDll);
        return false;
    }

    HHOOK hHook = SetWindowsHookExA(WH_GETMESSAGE, hookProc, hDll, threadId);
    if (!hHook) {
        FreeLibrary(hDll);
        return false;
    }

    PostThreadMessageA(threadId, WM_NULL, 0, 0);
    Sleep(500);

    UnhookWindowsHookEx(hHook);
    FreeLibrary(hDll);

    return true;
}

// Get main thread ID
DWORD GetMainThreadId(DWORD processId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    DWORD threadId = 0;
    FILETIME earliestTime = {MAXDWORD, MAXDWORD};

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                if (hThread) {
                    FILETIME creationTime, exitTime, kernelTime, userTime;
                    if (GetThreadTimes(hThread, &creationTime, &exitTime, &kernelTime, &userTime)) {
                        if (CompareFileTime(&creationTime, &earliestTime) < 0) {
                            earliestTime = creationTime;
                            threadId = te32.th32ThreadID;
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return threadId;
}

// Cleanup resources and restore defaults
void Cleanup() {
    if (g_pSharedMemory) {
        IslandEnvironment* pEnv = static_cast<IslandEnvironment*>(g_pSharedMemory);
        // Restore default values before cleanup
        pEnv->TargetFrameRate = 60;
        pEnv->EnableSetTargetFrameRate = TRUE;
        pEnv->FieldOfView = 45.0f;
        pEnv->EnableSetFieldOfView = TRUE;
        pEnv->FixLowFovScene = FALSE;
        pEnv->DisableFog = FALSE;
        pEnv->HideQuestBanner = FALSE;
        pEnv->RemoveOpenTeamProgress = FALSE;
        pEnv->DisableEventCameraMove = FALSE;
        pEnv->DisableShowDamageText = FALSE;
        pEnv->UsingTouchScreen = FALSE;
        pEnv->RedirectCombineEntry = FALSE;
        pEnv->State = IslandState::Stopped;
        
        UnmapViewOfFile(g_pSharedMemory);
        g_pSharedMemory = nullptr;
    }
    
    if (g_hMemoryMappedFile) {
        CloseHandle(g_hMemoryMappedFile);
        g_hMemoryMappedFile = nullptr;
    }
    
    if (g_hProcess) {
        CloseHandle(g_hProcess);
        g_hProcess = nullptr;
    }
}

// WinMain entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "HutaoLauncher";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassEx(&wc)) {
        return 0;
    }

    g_hMainWnd = CreateWindow(
        "HutaoLauncher",
        "Hutao Game Launcher v1.0 - @2025 Yoimiya (MIT License)",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        600, 400,
        NULL, NULL, hInstance, NULL
    );

    if (!g_hMainWnd) {
        return 0;
    }

    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}