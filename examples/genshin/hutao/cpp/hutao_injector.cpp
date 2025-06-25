#include <windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")

// Shared memory structure matching the DLL
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

class HutaoInjector {
private:
    static constexpr LPCSTR SHARED_MEMORY_NAME = "4F3E8543-40F7-4808-82DC-21E48A6037A7";
    
    // Chinese version offsets
    static constexpr FunctionOffsets ChineseOffsets = {
        87242192,   // MickeyWonder
        4830752,    // MickeyWonderPartner
        215314944,  // MickeyWonderPartner2
        17204528,   // SetFieldOfView
        277807600,  // SetEnableFogRendering
        277729120,  // SetTargetFrameRate
        118414576,  // OpenTeam
        118384496,  // OpenTeamPageAccordingly
        156982512,  // CheckCanEnter
        124927536,  // SetupQuestBanner
        277741040,  // FindGameObject
        277740368,  // SetActive
        186643424,  // EventCameraMove
        204578400,  // ShowOneDamageTextEx
        144617776,  // SwitchInputDeviceToTouchScreen
        127845632,  // MickeyWonderCombineEntry
        201143472   // MickeyWonderCombineEntryPartner
    };

    HANDLE hMemoryMappedFile;
    LPVOID pSharedMemory;
    HANDLE hProcess;
    DWORD processId;

public:
    HutaoInjector() : hMemoryMappedFile(nullptr), pSharedMemory(nullptr), 
                     hProcess(nullptr), processId(0) {}

    ~HutaoInjector() {
        Cleanup();
    }

    bool Initialize() {
        return CreatePersistentSharedMemory();
    }

    bool LaunchAndInject(const std::string& gamePath, const std::string& dllPath,
                        float fov, int fps, bool enableFov, bool enableFps,
                        bool disableFog, bool fixLowFov, bool hideBanner, bool removeTeamAnim,
                        bool disableEventCamera, bool hideDamage, bool touchScreen, bool redirectCombine) {
        
        // Configure initial environment
        ConfigureInitialEnvironment(fov, fps, enableFov, enableFps,
                                  disableFog, fixLowFov, hideBanner, removeTeamAnim,
                                  disableEventCamera, hideDamage, touchScreen, redirectCombine);

        // Launch game
        if (!LaunchGame(gamePath)) {
            return false;
        }

        // Inject DLL
        if (!InjectDLLWithHook(dllPath)) {
            return false;
        }

        return true;
    }

    void RunConfigLoop() {
        std::cout << "\n=== Hutao Injector & Configuration Tool ===" << std::endl;
        std::cout << "Type 'help' for commands, 'status' for current config, or 'quit' to exit." << std::endl;
        std::cout << "Game launched with PID: " << processId << std::endl;
        std::cout << "\n[NOTE] Remember to use 'quit' command to restore defaults before closing!" << std::endl;

        std::string input;
        while (true) {
            std::cout << "hutao> ";
            if (!std::getline(std::cin, input)) {
                break;  // EOF or input stream closed
            }
            
            if (!input.empty()) {
                if (input == "quit" || input == "exit") {
                    std::cout << "Restoring defaults and preparing to exit..." << std::endl;
                    ProcessCommand("reset");
                    break;
                }
                ProcessCommand(input);
            }
        }

        std::cout << "\nExiting configuration loop..." << std::endl;
    }

private:
    bool CreatePersistentSharedMemory() {
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = NULL;
        sa.bInheritHandle = TRUE;

        hMemoryMappedFile = CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            &sa,
            PAGE_READWRITE,
            0,
            sizeof(IslandEnvironment),
            SHARED_MEMORY_NAME
        );

        if (!hMemoryMappedFile) {
            std::cout << "Failed to create memory mapped file: " << GetLastError() << std::endl;
            return false;
        }

        pSharedMemory = MapViewOfFile(
            hMemoryMappedFile,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            sizeof(IslandEnvironment)
        );

        if (!pSharedMemory) {
            std::cout << "Failed to map view of file: " << GetLastError() << std::endl;
            return false;
        }

        std::cout << "[OK] Persistent shared memory created" << std::endl;
        return true;
    }

    void ConfigureInitialEnvironment(float fov, int fps, bool enableFov, bool enableFps,
                                   bool disableFog, bool fixLowFov, bool hideBanner, bool removeTeamAnim,
                                   bool disableEventCamera, bool hideDamage, bool touchScreen, bool redirectCombine) {
        if (!pSharedMemory) return;

        IslandEnvironment* pEnv = static_cast<IslandEnvironment*>(pSharedMemory);
        ZeroMemory(pEnv, sizeof(IslandEnvironment));

        pEnv->FunctionOffsets = ChineseOffsets;
        pEnv->EnableSetFieldOfView = enableFov ? TRUE : FALSE;
        pEnv->FieldOfView = fov;
        pEnv->FixLowFovScene = fixLowFov ? TRUE : FALSE;
        pEnv->DisableFog = disableFog ? TRUE : FALSE;
        pEnv->EnableSetTargetFrameRate = enableFps ? TRUE : FALSE;
        pEnv->TargetFrameRate = fps;
        pEnv->RemoveOpenTeamProgress = removeTeamAnim ? TRUE : FALSE;
        pEnv->HideQuestBanner = hideBanner ? TRUE : FALSE;
        pEnv->DisableEventCameraMove = disableEventCamera ? TRUE : FALSE;
        pEnv->DisableShowDamageText = hideDamage ? TRUE : FALSE;
        pEnv->UsingTouchScreen = touchScreen ? TRUE : FALSE;
        pEnv->RedirectCombineEntry = redirectCombine ? TRUE : FALSE;
        pEnv->State = IslandState::Started;

        std::cout << "\n[OK] Initial configuration applied:" << std::endl;
        std::cout << "  - FPS: " << fps << (enableFps ? " (enabled)" : " (disabled)") << std::endl;
        std::cout << "  - FOV: " << fov << (enableFov ? " (enabled)" : " (disabled)") << std::endl;
        std::cout << "  - Fix low FOV scenes: " << (fixLowFov ? "enabled" : "disabled") << std::endl;
        std::cout << "  - Other settings configured" << std::endl;
    }

    bool LaunchGame(const std::string& gamePath) {
        std::string gameDir = gamePath.substr(0, gamePath.find_last_of("\\/"));
        
        std::cout << "Launching game: " << gamePath << std::endl;
        std::cout << "Working directory: " << gameDir << std::endl;

        STARTUPINFOA si = {0};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {0};

        if (!CreateProcessA(
            gamePath.c_str(),
            nullptr,
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            gameDir.c_str(),
            &si,
            &pi)) {
            std::cout << "Failed to launch game. Error: " << GetLastError() << std::endl;
            return false;
        }

        CloseHandle(pi.hThread);
        hProcess = pi.hProcess;
        processId = pi.dwProcessId;

        std::cout << "Game launched successfully (PID: " << processId << ")" << std::endl;
        SetPriorityClass(hProcess, HIGH_PRIORITY_CLASS);

        std::cout << "Waiting for game initialization..." << std::endl;
        Sleep(10000);

        return WaitForMainModule("YuanShen.exe");
    }

    bool InjectDLLWithHook(const std::string& dllPath) {
        if (processId == 0) {
            std::cout << "No target process identified" << std::endl;
            return false;
        }

        std::cout << "Injecting DLL via SetWindowsHookEx: " << dllPath << std::endl;

        HMODULE hDll = LoadLibraryA(dllPath.c_str());
        if (!hDll) {
            std::cout << "Failed to load DLL locally: " << GetLastError() << std::endl;
            return false;
        }

        HOOKPROC hookProc = nullptr;
        auto pGetHook = (HRESULT(WINAPI*)(HOOKPROC*))GetProcAddress(hDll, "DllGetWindowsHookForHutao");
        if (!pGetHook) {
            pGetHook = (HRESULT(WINAPI*)(HOOKPROC*))GetProcAddress(hDll, "IslandGetWindowHook");
        }

        if (pGetHook && SUCCEEDED(pGetHook(&hookProc))) {
            std::cout << "Hook function retrieved from DLL" << std::endl;
        } else {
            std::cout << "Failed to get hook function from DLL" << std::endl;
            FreeLibrary(hDll);
            return false;
        }

        DWORD threadId = GetMainThreadId(processId);
        if (threadId == 0) {
            std::cout << "Failed to get main thread ID" << std::endl;
            FreeLibrary(hDll);
            return false;
        }

        HHOOK hHook = SetWindowsHookExA(WH_GETMESSAGE, hookProc, hDll, threadId);
        if (!hHook) {
            DWORD error = GetLastError();
            std::cout << "SetWindowsHookEx failed: " << error << std::endl;
            FreeLibrary(hDll);
            return false;
        }

        PostThreadMessageA(threadId, WM_NULL, 0, 0);
        Sleep(500);

        std::cout << "[OK] DLL injected successfully" << std::endl;

        UnhookWindowsHookEx(hHook);
        FreeLibrary(hDll);

        return true;
    }

    void ProcessCommand(const std::string& command) {
        if (!pSharedMemory) return;

        IslandEnvironment* pEnv = static_cast<IslandEnvironment*>(pSharedMemory);
        std::istringstream iss(command);
        std::string cmd;
        iss >> cmd;

        if (cmd == "fps") {
            int value;
            if (iss >> value) {
                if (value < 30) {
                    std::cout << "Error: FPS must be at least 30. Current value: " << value << std::endl;
                    return;
                }
                pEnv->TargetFrameRate = value;
                pEnv->EnableSetTargetFrameRate = TRUE;
                std::cout << "FPS set to: " << value << " (enabled)" << std::endl;
            } else {
                std::cout << "Usage: fps <value> - Set target frame rate (minimum 30, e.g., fps 120)" << std::endl;
            }
        }
        else if (cmd == "fov") {
            float value;
            if (iss >> value) {
                if (value < 1.0f) {
                    std::cout << "Error: FOV must be at least 1.0. Current value: " << value << std::endl;
                    return;
                }
                pEnv->FieldOfView = value;
                pEnv->EnableSetFieldOfView = TRUE;
                std::cout << "FOV set to: " << value << " (enabled)" << std::endl;
            } else {
                std::cout << "Usage: fov <value> - Set field of view (minimum 1.0, e.g., fov 60.0)" << std::endl;
            }
        }
        else if (cmd == "fixfov") {
            std::string state;
            if (iss >> state) {
                pEnv->FixLowFovScene = (state == "on" || state == "enable") ? TRUE : FALSE;
                std::cout << "Fix low FOV scenes: " << (pEnv->FixLowFovScene ? "enabled" : "disabled") << std::endl;
            } else {
                std::cout << "Usage: fixfov <on|off> - Fix low FOV scenes (fov <= 30)" << std::endl;
            }
        }
        else if (cmd == "fog") {
            std::string state;
            if (iss >> state) {
                pEnv->DisableFog = (state == "off" || state == "disable") ? TRUE : FALSE;
                std::cout << "Fog rendering: " << (pEnv->DisableFog ? "disabled" : "enabled") << std::endl;
            } else {
                std::cout << "Usage: fog <on|off>" << std::endl;
            }
        }
        else if (cmd == "banner") {
            std::string state;
            if (iss >> state) {
                pEnv->HideQuestBanner = (state == "hide") ? TRUE : FALSE;
                std::cout << "Quest banner: " << (pEnv->HideQuestBanner ? "hidden" : "visible") << std::endl;
            } else {
                std::cout << "Usage: banner <show|hide>" << std::endl;
            }
        }
        else if (cmd == "team") {
            std::string state;
            if (iss >> state) {
                pEnv->RemoveOpenTeamProgress = (state == "remove") ? TRUE : FALSE;
                std::cout << "Team animation: " << (pEnv->RemoveOpenTeamProgress ? "removed" : "normal") << std::endl;
            } else {
                std::cout << "Usage: team <normal|remove>" << std::endl;
            }
        }
        else if (cmd == "camera") {
            std::string state;
            if (iss >> state) {
                pEnv->DisableEventCameraMove = (state == "disable") ? TRUE : FALSE;
                std::cout << "Event camera: " << (pEnv->DisableEventCameraMove ? "disabled" : "enabled") << std::endl;
            } else {
                std::cout << "Usage: camera <enable|disable>" << std::endl;
            }
        }
        else if (cmd == "damage") {
            std::string state;
            if (iss >> state) {
                pEnv->DisableShowDamageText = (state == "hide") ? TRUE : FALSE;
                std::cout << "Damage numbers: " << (pEnv->DisableShowDamageText ? "hidden" : "visible") << std::endl;
            } else {
                std::cout << "Usage: damage <show|hide>" << std::endl;
            }
        }
        else if (cmd == "craft") {
            std::string state;
            if (iss >> state) {
                pEnv->RedirectCombineEntry = (state == "redirect") ? TRUE : FALSE;
                std::cout << "Crafting table: " << (pEnv->RedirectCombineEntry ? "redirected to synthesis" : "normal") << std::endl;
            } else {
                std::cout << "Usage: craft <normal|redirect>" << std::endl;
            }
        }
        else if (cmd == "status") {
            ShowStatus(pEnv);
        }
        else if (cmd == "reset") {
            std::cout << "Resetting all settings to default values..." << std::endl;
            // Restore default values
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
            std::cout << "[OK] All settings have been reset to defaults" << std::endl;
        }
        else if (cmd == "help" || cmd == "?") {
            ShowHelp();
        }
        else {
            std::cout << "Unknown command: '" << cmd << "'. Type 'help' for available commands." << std::endl;
        }
    }

    void ShowStatus(IslandEnvironment* pEnv) {
        std::cout << "\n=== Current Configuration ===" << std::endl;
        std::cout << "FPS: " << pEnv->TargetFrameRate << (pEnv->EnableSetTargetFrameRate ? " (enabled)" : " (disabled)") << std::endl;
        std::cout << "FOV: " << pEnv->FieldOfView << (pEnv->EnableSetFieldOfView ? " (enabled)" : " (disabled)") << std::endl;
        std::cout << "Fix low FOV scenes: " << (pEnv->FixLowFovScene ? "enabled" : "disabled") << std::endl;
        std::cout << "Fog: " << (pEnv->DisableFog ? "disabled" : "enabled") << std::endl;
        std::cout << "Banner: " << (pEnv->HideQuestBanner ? "hidden" : "visible") << std::endl;
        std::cout << "Team animation: " << (pEnv->RemoveOpenTeamProgress ? "removed" : "normal") << std::endl;
        std::cout << "Event camera: " << (pEnv->DisableEventCameraMove ? "disabled" : "enabled") << std::endl;
        std::cout << "Damage numbers: " << (pEnv->DisableShowDamageText ? "hidden" : "visible") << std::endl;
        std::cout << "Touch screen: " << (pEnv->UsingTouchScreen ? "enabled" : "disabled") << std::endl;
        std::cout << "Crafting table: " << (pEnv->RedirectCombineEntry ? "redirected to synthesis" : "normal") << std::endl;
        std::cout << "State: " << (int)pEnv->State << std::endl;
        std::cout << "Game PID: " << processId << std::endl;
    }

    void ShowHelp() {
        std::cout << "\n=== Available Commands ===" << std::endl;
        std::cout << "fps <value>          - Set target FPS (e.g., fps 120)" << std::endl;
        std::cout << "fov <value>          - Set field of view (e.g., fov 60.0)" << std::endl;
        std::cout << "fixfov <on|off>      - Fix low FOV scenes (fov <= 30)" << std::endl;
        std::cout << "fog <on|off>         - Enable/disable fog rendering" << std::endl;
        std::cout << "banner <show|hide>   - Show/hide quest banner" << std::endl;
        std::cout << "team <normal|remove> - Control team opening animation" << std::endl;
        std::cout << "camera <enable|disable> - Control event camera movement" << std::endl;
        std::cout << "damage <show|hide>   - Control damage number display" << std::endl;
        std::cout << "craft <normal|redirect> - Control crafting table redirect" << std::endl;
        std::cout << "status               - Show current configuration" << std::endl;
        std::cout << "reset                - Reset all settings to defaults" << std::endl;
        std::cout << "help, ?              - Show this help message" << std::endl;
        std::cout << "quit, exit           - Restore defaults and exit" << std::endl;
        std::cout << "\n[IMPORTANT] Always use 'quit' to properly restore defaults!" << std::endl;
        std::cout << "===========================" << std::endl;
    }

    void Cleanup() {
        std::cout << "[Cleanup] Starting cleanup process..." << std::endl;
        
        if (pSharedMemory) {
            std::cout << "[Cleanup] Setting DLL state to stopped..." << std::endl;
            IslandEnvironment* pEnv = static_cast<IslandEnvironment*>(pSharedMemory);
            pEnv->State = IslandState::Stopped;
            
            UnmapViewOfFile(pSharedMemory);
            pSharedMemory = nullptr;
            std::cout << "[Cleanup] SharedMemory unmapped" << std::endl;
        }
        
        if (hMemoryMappedFile) {
            CloseHandle(hMemoryMappedFile);
            hMemoryMappedFile = nullptr;
            std::cout << "[Cleanup] Memory mapped file closed" << std::endl;
        }
        
        if (hProcess) {
            CloseHandle(hProcess);
            hProcess = nullptr;
            std::cout << "[Cleanup] Game process handle closed" << std::endl;
        }
        
        std::cout << "[Cleanup] All resources cleaned up successfully" << std::endl;
    }

    // Helper functions
    bool WaitForMainModule(const std::string& exeName) {
        std::cout << "Waiting for main module: " << exeName << std::endl;
        
        int timeout = 300;
        while (timeout > 0) {
            if (GetMainModuleInfo(exeName)) {
                std::cout << "Main module loaded successfully" << std::endl;
                return true;
            }
            Sleep(100);
            timeout--;
        }

        std::cout << "Timeout waiting for main module!" << std::endl;
        return false;
    }

    bool GetMainModuleInfo(const std::string& exeName) {
        HMODULE hMods[1024];
        DWORD cbNeeded;
        
        if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            return false;
        }

        DWORD moduleCount = cbNeeded / sizeof(HMODULE);
        
        for (DWORD i = 0; i < moduleCount; i++) {
            CHAR moduleName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], moduleName, sizeof(moduleName))) {
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
};

// Helper functions for input
std::string GetInput(const std::string& prompt, const std::string& defaultValue) {
    std::cout << prompt << " [default: " << defaultValue << "]: ";
    std::string input;
    std::getline(std::cin, input);
    return input.empty() ? defaultValue : input;
}

int GetIntInput(const std::string& prompt, int defaultValue) {
    std::string input = GetInput(prompt, std::to_string(defaultValue));
    try {
        return std::stoi(input);
    } catch (...) {
        return defaultValue;
    }
}

float GetFloatInput(const std::string& prompt, float defaultValue) {
    std::string input = GetInput(prompt, std::to_string(defaultValue));
    try {
        return std::stof(input);
    } catch (...) {
        return defaultValue;
    }
}

bool GetBoolInput(const std::string& prompt, bool defaultValue) {
    std::string fullPrompt = prompt + " [" + (defaultValue ? "Y/n" : "y/N") + "]: ";
    std::cout << fullPrompt;
    
    std::string input;
    std::getline(std::cin, input);
    
    if (input.empty()) return defaultValue;
    return (input[0] == 'y' || input[0] == 'Y');
}

int main(int argc, char* argv[]) {
    std::cout << "=== Hutao Injector & Configuration Tool ===" << std::endl;
    
    std::string gamePath, dllPath;
    
    if (argc >= 3) {
        gamePath = argv[1];
        dllPath = argv[2];
    } else {
        std::cout << "Usage: hutao_injector.exe <game_path> <dll_path>" << std::endl;
        std::cout << "Or run without arguments for interactive mode" << std::endl;
        
        gamePath = GetInput("Game path", "D:\\Program Files\\Genshin Impact\\Genshin Impact Game\\YuanShen.exe");
        dllPath = GetInput("DLL path", "hutao_minhook.dll");
    }
    
    // Configuration setup with validation
    int targetFps;
    do {
        targetFps = GetIntInput("Target FPS (minimum 30)", 60);
        if (targetFps < 30) {
            std::cout << "Error: FPS must be at least 30. Please try again." << std::endl;
        }
    } while (targetFps < 30);
    
    float fieldOfView;
    do {
        fieldOfView = GetFloatInput("Field of View (minimum 1.0)", 45.0f);
        if (fieldOfView < 1.0f) {
            std::cout << "Error: FOV must be at least 1.0. Please try again." << std::endl;
        }
    } while (fieldOfView < 1.0f);
    
    bool enableFps = targetFps > 0;
    bool enableFov = fieldOfView > 0;
    bool disableFog = GetBoolInput("Disable fog rendering?", false);
    bool fixLowFov = GetBoolInput("Fix low FOV scenes (fov <= 30)?", false);
    bool hideBanner = GetBoolInput("Hide quest banner?", false);
    bool removeTeamAnim = GetBoolInput("Remove team open animation?", false);
    bool disableEventCamera = GetBoolInput("Disable event camera movement?", false);
    bool hideDamage = GetBoolInput("Hide damage numbers?", false);
    bool touchScreen = GetBoolInput("Enable touch screen mode?", false);
    bool redirectCombine = GetBoolInput("Redirect crafting table to synthesis station?", false);

    // Check if DLL exists
    if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "DLL not found: " << dllPath << std::endl;
        return 1;
    }

    HutaoInjector injector;
    
    if (!injector.Initialize()) {
        std::cerr << "Failed to initialize injector." << std::endl;
        return 1;
    }
    
    if (!injector.LaunchAndInject(gamePath, dllPath, fieldOfView, targetFps, 
                                 enableFov, enableFps, disableFog, fixLowFov, hideBanner, 
                                 removeTeamAnim, disableEventCamera, hideDamage, 
                                 touchScreen, redirectCombine)) {
        std::cerr << "Failed to launch and inject." << std::endl;
        return 1;
    }

    std::cout << "\n[OK] Launch and injection completed!" << std::endl;
    std::cout << "Game is running with initial configuration." << std::endl;
    std::cout << "You can now modify settings using commands below." << std::endl;
    
    // Run configuration loop
    injector.RunConfigLoop();

    return 0;
}