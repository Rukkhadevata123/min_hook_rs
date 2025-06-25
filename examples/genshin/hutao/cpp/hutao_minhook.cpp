#include <windows.h>
#include <string>
#include <cmath>
#include <mutex>
#include "MinHook.h"

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "MinHook.x64.lib")

// IL2CPP structures
typedef struct tagIl2CppObject {
    LPVOID klass;
    LPVOID monitor;
} Il2CppObject;

typedef struct tagIl2CppArraySize {
    Il2CppObject object;
    LPVOID bounds;
    SIZE_T max_length;
    UCHAR vector[32];
} Il2CppArraySize;

typedef struct tagIl2CppString {
    Il2CppObject object;
    INT32 length;
    WCHAR chars[32];
} Il2CppString;

// Function types
typedef Il2CppArraySize* (*MickeyWonderMethod)(INT32 value);
typedef Il2CppString* (*MickeyWonderMethodPartner)(PCSTR value);
typedef VOID(*MickeyWonderMethodPartner2)(LPVOID mickey, LPVOID house, LPVOID spell);
typedef VOID(*SetFieldOfViewMethod)(LPVOID this__, FLOAT value);
typedef VOID(*SetEnableFogRenderingMethod)(bool value);
typedef VOID(*SetTargetFrameRateMethod)(INT32 value);
typedef VOID(*OpenTeamMethod)();
typedef VOID(*OpenTeamPageAccordinglyMethod)(bool value);
typedef bool (*CheckCanEnterMethod)();
typedef VOID(*SetupQuestBannerMethod)(LPVOID this__);
typedef LPVOID(*FindGameObjectMethod)(Il2CppString* name);
typedef VOID(*SetActiveMethod)(LPVOID this__, bool value);
typedef bool (*EventCameraMoveMethod)(LPVOID this__, LPVOID event);
typedef VOID(*ShowOneDamageTextExMethod)(LPVOID this__, int type, int damageType, int showType, float damage, Il2CppString* showText, LPVOID worldPos, LPVOID attackee, int elementReactionType);
typedef VOID(*SwitchInputDeviceToTouchScreenMethod)(LPVOID this__);
typedef VOID(*MickeyWonderCombineEntryMethod)(LPVOID this__);
typedef bool(*MickeyWonderCombineEntryMethodPartner)(Il2CppString* name, LPVOID arg2, LPVOID arg3, LPVOID arg4, LPVOID arg5);

// Environment structure
enum IslandState : int {
    None = 0,
    Error = 1,
    Started = 2,
    Stopped = 3,
};

struct FunctionOffsets {
    UINT32 MickeyWonder;
    UINT32 MickeyWonderPartner;
    UINT32 MickeyWonderPartner2;
    UINT32 SetFieldOfView;
    UINT32 SetEnableFogRendering;
    UINT32 SetTargetFrameRate;
    UINT32 OpenTeam;
    UINT32 OpenTeamPageAccordingly;
    UINT32 CheckCanEnter;
    UINT32 SetupQuestBanner;
    UINT32 FindGameObject;
    UINT32 SetActive;
    UINT32 EventCameraMove;
    UINT32 ShowOneDamageTextEx;
    UINT32 SwitchInputDeviceToTouchScreen;
    UINT32 MickeyWonderCombineEntry;
    UINT32 MickeyWonderCombineEntryPartner;
};

struct IslandEnvironment {
    enum IslandState State;
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

// Original function pointers
struct OriginalFunctions {
    MickeyWonderMethod MickeyWonder;
    MickeyWonderMethodPartner MickeyWonderPartner;
    MickeyWonderMethodPartner2 MickeyWonderPartner2;
    SetFieldOfViewMethod SetFieldOfView;
    SetEnableFogRenderingMethod SetEnableFogRendering;
    SetTargetFrameRateMethod SetTargetFrameRate;
    OpenTeamMethod OpenTeam;
    OpenTeamPageAccordinglyMethod OpenTeamPageAccordingly;
    CheckCanEnterMethod CheckCanEnter;
    SetupQuestBannerMethod SetupQuestBanner;
    FindGameObjectMethod FindGameObject;
    SetActiveMethod SetActive;
    EventCameraMoveMethod EventCameraMove;
    ShowOneDamageTextExMethod ShowOneDamageTextEx;
    SwitchInputDeviceToTouchScreenMethod SwitchInputDeviceToTouchScreen;
    MickeyWonderCombineEntryMethod MickeyWonderCombineEntry;
    MickeyWonderCombineEntryMethodPartner MickeyWonderCombineEntryPartner;
};

// Global variables
const wchar_t* ISLAND_ENVIRONMENT_NAME = L"4F3E8543-40F7-4808-82DC-21E48A6037A7";
IslandEnvironment* pEnvironment = nullptr;
OriginalFunctions originals = {};
std::string minnie;
std::once_flag ofTouchScreen;

// Memory protection disabling
EXTERN_C NTSYSAPI NTSTATUS NTAPI LdrAddRefDll(ULONG Flags, PVOID DllHandle);
#define LDR_ADDREF_DLL_PIN 0x00000001

VOID DisableProtectVirtualMemory() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    FARPROC pNtProtectVirtualMemory = GetProcAddress(ntdll, "NtProtectVirtualMemory");
    FARPROC pNtQuerySection = GetProcAddress(ntdll, "NtQuerySection");

    DWORD old;
    VirtualProtect(pNtProtectVirtualMemory, 1, PAGE_EXECUTE_READWRITE, &old);
    *(PUINT64)pNtProtectVirtualMemory = *(PUINT64)pNtQuerySection & ~(0xFFUi64 << 32) | (UINT64)(*(PUINT32)((UINT64)pNtQuerySection + 4) - 1) << 32;
    VirtualProtect(pNtProtectVirtualMemory, 1, old, &old);
}

// Utility functions
bool IsValidReadPtr(LPVOID ptr, SIZE_T size) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ptr, &mbi, sizeof(mbi))) {
        return (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY)) != 0;
    }
    return false;
}

// Hook endpoints
VOID MickeyWonderPartner2Endpoint(LPVOID mickey, LPVOID house, LPVOID spell) {
    BOOL bFound = FALSE;
    
    Il2CppString* pString = originals.MickeyWonderPartner(minnie.c_str());
    Il2CppString** ppCurrent = NULL;
    
    for (int offset = 0x10; offset < 0x233; offset += 0x8) {
        ppCurrent = (Il2CppString**)((PBYTE)house + offset);
        if (*ppCurrent == NULL || !IsValidReadPtr(*ppCurrent, sizeof(Il2CppString))) {
            continue;
        }
        
        if ((*ppCurrent)->length != 66) {
            continue;
        }
        
        bFound = TRUE;
        break;
    }
    
    if (!bFound) {
        return originals.MickeyWonderPartner2(mickey, house, spell);
    }
    
    if (ppCurrent) {
        *ppCurrent = pString;
    }
    
    originals.MickeyWonderPartner2(mickey, house, spell);
}

VOID SetFieldOfViewEndpoint(LPVOID pThis, FLOAT value) {
    std::call_once(ofTouchScreen, [&]() {
        if (pEnvironment->UsingTouchScreen) {
            __try {
                originals.SwitchInputDeviceToTouchScreen(NULL);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // Ignore exception
            }
        }
    });
    
    if (pEnvironment->EnableSetTargetFrameRate) {
        originals.SetTargetFrameRate(pEnvironment->TargetFrameRate);
    }
    
    if (!pEnvironment->EnableSetFieldOfView) {
        return originals.SetFieldOfView(pThis, value);
    }
    
    if (std::floor(value) <= 30.0f) {
        originals.SetEnableFogRendering(false);
        originals.SetFieldOfView(pThis, pEnvironment->FixLowFovScene ? value : pEnvironment->FieldOfView);
    } else {
        originals.SetEnableFogRendering(!pEnvironment->DisableFog);
        originals.SetFieldOfView(pThis, pEnvironment->FieldOfView);
    }
}

VOID OpenTeamEndpoint() {
    if (pEnvironment->RemoveOpenTeamProgress && originals.CheckCanEnter()) {
        originals.OpenTeamPageAccordingly(false);
    } else {
        originals.OpenTeam();
    }
}

VOID SetupQuestBannerEndpoint(LPVOID pThis) {
    if (!pEnvironment->HideQuestBanner) {
        originals.SetupQuestBanner(pThis);
    } else {
        Il2CppString* bannerString = originals.MickeyWonderPartner("Canvas/Pages/InLevelMapPage/GrpMap/GrpPointTips/Layout/QuestBanner");
        LPVOID banner = originals.FindGameObject(bannerString);
        if (banner) {
            originals.SetActive(banner, false);
        }
    }
}

bool EventCameraMoveEndpoint(LPVOID pThis, LPVOID event) {
    if (pEnvironment->DisableEventCameraMove) {
        return true;
    } else {
        return originals.EventCameraMove(pThis, event);
    }
}

VOID ShowOneDamageTextExEndpoint(LPVOID pThis, int type, int damageType, int showType, float damage, Il2CppString* showText, LPVOID worldPos, LPVOID attackee, int elementReactionType) {
    if (pEnvironment->DisableShowDamageText) {
        return;
    }
    
    originals.ShowOneDamageTextEx(pThis, type, damageType, showType, damage, showText, worldPos, attackee, elementReactionType);
}

VOID MickeyWonderCombineEntryEndpoint(LPVOID pThis) {
    if (pEnvironment->RedirectCombineEntry) {
        originals.MickeyWonderCombineEntryPartner(originals.MickeyWonderPartner("SynthesisPage"), NULL, NULL, NULL, NULL);
        return;
    }
    
    originals.MickeyWonderCombineEntry(pThis);
}

bool InstallMinHooks(UINT64 base, IslandEnvironment* pEnvironment) {
    if (MH_Initialize() != MH_OK) {
        return false;
    }

    LPVOID pTarget;
    MH_STATUS status;

    // MickeyWonderPartner2
    pTarget = (LPVOID)(base + pEnvironment->FunctionOffsets.MickeyWonderPartner2);
    status = MH_CreateHook(pTarget, MickeyWonderPartner2Endpoint, (LPVOID*)&originals.MickeyWonderPartner2);
    if (status != MH_OK) return false;

    // SetFieldOfView
    pTarget = (LPVOID)(base + pEnvironment->FunctionOffsets.SetFieldOfView);
    status = MH_CreateHook(pTarget, SetFieldOfViewEndpoint, (LPVOID*)&originals.SetFieldOfView);
    if (status != MH_OK) return false;

    // OpenTeam
    pTarget = (LPVOID)(base + pEnvironment->FunctionOffsets.OpenTeam);
    status = MH_CreateHook(pTarget, OpenTeamEndpoint, (LPVOID*)&originals.OpenTeam);
    if (status != MH_OK) return false;

    // SetupQuestBanner
    pTarget = (LPVOID)(base + pEnvironment->FunctionOffsets.SetupQuestBanner);
    status = MH_CreateHook(pTarget, SetupQuestBannerEndpoint, (LPVOID*)&originals.SetupQuestBanner);
    if (status != MH_OK) return false;

    // EventCameraMove
    pTarget = (LPVOID)(base + pEnvironment->FunctionOffsets.EventCameraMove);
    status = MH_CreateHook(pTarget, EventCameraMoveEndpoint, (LPVOID*)&originals.EventCameraMove);
    if (status != MH_OK) return false;

    // ShowOneDamageTextEx
    pTarget = (LPVOID)(base + pEnvironment->FunctionOffsets.ShowOneDamageTextEx);
    status = MH_CreateHook(pTarget, ShowOneDamageTextExEndpoint, (LPVOID*)&originals.ShowOneDamageTextEx);
    if (status != MH_OK) return false;

    // MickeyWonderCombineEntry
    pTarget = (LPVOID)(base + pEnvironment->FunctionOffsets.MickeyWonderCombineEntry);
    status = MH_CreateHook(pTarget, MickeyWonderCombineEntryEndpoint, (LPVOID*)&originals.MickeyWonderCombineEntry);
    if (status != MH_OK) return false;

    originals.MickeyWonder = reinterpret_cast<MickeyWonderMethod>(base + pEnvironment->FunctionOffsets.MickeyWonder);
    originals.MickeyWonderPartner = reinterpret_cast<MickeyWonderMethodPartner>(base + pEnvironment->FunctionOffsets.MickeyWonderPartner);
    originals.SetEnableFogRendering = reinterpret_cast<SetEnableFogRenderingMethod>(base + pEnvironment->FunctionOffsets.SetEnableFogRendering);
    originals.SetTargetFrameRate = reinterpret_cast<SetTargetFrameRateMethod>(base + pEnvironment->FunctionOffsets.SetTargetFrameRate);
    originals.OpenTeamPageAccordingly = reinterpret_cast<OpenTeamPageAccordinglyMethod>(base + pEnvironment->FunctionOffsets.OpenTeamPageAccordingly);
    originals.CheckCanEnter = reinterpret_cast<CheckCanEnterMethod>(base + pEnvironment->FunctionOffsets.CheckCanEnter);
    originals.FindGameObject = reinterpret_cast<FindGameObjectMethod>(base + pEnvironment->FunctionOffsets.FindGameObject);
    originals.SetActive = reinterpret_cast<SetActiveMethod>(base + pEnvironment->FunctionOffsets.SetActive);
    originals.SwitchInputDeviceToTouchScreen = reinterpret_cast<SwitchInputDeviceToTouchScreenMethod>(base + pEnvironment->FunctionOffsets.SwitchInputDeviceToTouchScreen);
    originals.MickeyWonderCombineEntryPartner = reinterpret_cast<MickeyWonderCombineEntryMethodPartner>(base + pEnvironment->FunctionOffsets.MickeyWonderCombineEntryPartner);

    status = MH_EnableHook(MH_ALL_HOOKS);
    if (status != MH_OK) {
        MH_Uninitialize();
        return false;
    }

    return true;
}

// Static hook procedure for exports
static LRESULT WINAPI IslandGetWindowHookImpl(int code, WPARAM wParam, LPARAM lParam) {
    return CallNextHookEx(NULL, code, wParam, lParam);
}

// Main DLL thread
DWORD WINAPI IslandThread(LPVOID lpParam) {
    // Open shared memory
    HANDLE hFile = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, ISLAND_ENVIRONMENT_NAME);
    if (!hFile) {
        return GetLastError();
    }
    
    LPVOID lpView = MapViewOfFile(hFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (!lpView) {
        CloseHandle(hFile);
        return GetLastError();
    }
    
    pEnvironment = static_cast<IslandEnvironment*>(lpView);
    pEnvironment->State = Started;
    
    // Initialize base address
    UINT64 base = (UINT64)GetModuleHandleW(NULL);
    
    // Build minnie string
    for (INT32 n = 0; n < 3; n++) {
        MickeyWonderMethod mickeyWonder = reinterpret_cast<MickeyWonderMethod>(base + pEnvironment->FunctionOffsets.MickeyWonder);
        __try {
            Il2CppArraySize* const result = mickeyWonder(n);
            if (result) {
                minnie += std::string(reinterpret_cast<char*>(&result->vector[0]), result->max_length);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Failed to call MickeyWonder, set error state
            pEnvironment->State = Error;
            pEnvironment->LastError = GetExceptionCode();
            UnmapViewOfFile(lpView);
            CloseHandle(hFile);
            return GetExceptionCode();
        }
    }
    
    // Install hooks using MinHook
    if (!InstallMinHooks(base, pEnvironment)) {
        pEnvironment->State = Error;
        pEnvironment->LastError = GetLastError();
        UnmapViewOfFile(lpView);
        CloseHandle(hFile);
        return GetLastError();
    }
    
    // Wait indefinitely
    WaitForSingleObject(GetCurrentThread(), INFINITE);
    
    // Cleanup
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    
    pEnvironment->State = Stopped;
    UnmapViewOfFile(lpView);
    CloseHandle(hFile);
    
    FreeLibraryAndExitThread(static_cast<HMODULE>(lpParam), 0);
    return 0;
}

// Export functions
extern "C" {
    __declspec(dllexport) HRESULT WINAPI DllGetWindowsHookForHutao(HOOKPROC* pHookProc) {
        *pHookProc = IslandGetWindowHookImpl;
        return S_OK;
    }
    
    __declspec(dllexport) HRESULT WINAPI IslandGetWindowHook(HOOKPROC* pHookProc) {
        *pHookProc = IslandGetWindowHookImpl;
        return S_OK;
    }
    
    __declspec(dllexport) HRESULT WINAPI IslandGetFunctionOffsetsSize(UINT64* pCount) {
        *pCount = sizeof(FunctionOffsets);
        return S_OK;
    }
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        
        // Pin DLL in memory
        LdrAddRefDll(LDR_ADDREF_DLL_PIN, hModule);
        
        // Disable memory protection
        DisableProtectVirtualMemory();
        
        // Create main thread
        CreateThread(NULL, 0, IslandThread, hModule, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        // Cleanup MinHook
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        Sleep(500);
        break;
    }
    return TRUE;
}