#include <windows.h>
#include <cmath>
#include <psapi.h>
#include "MinHook.h"

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
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

const char* ISLAND_ENVIRONMENT_NAME = "4F3E8543-40F7-4808-82DC-21E48A6037A7";
IslandEnvironment* pEnvironment = NULL;
OriginalFunctions originals = {0};
char minnie_buffer[1024] = {0};
int minnie_length = 0;
BOOL touch_screen_initialized = FALSE;

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

struct ExceptionInfo {
    DWORD code;
    LPVOID address;
    ULONG_PTR info0;
    ULONG_PTR info1;
};

// 修改 LogException 函数以支持更详细的信息
void LogException(const char* location, const ExceptionInfo* exInfo) {
    HANDLE hFile = CreateFileA("hutao_exceptions.log", 
        GENERIC_WRITE, FILE_SHARE_READ, NULL, 
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        SetFilePointer(hFile, 0, NULL, FILE_END);
        
        char buffer[1024];
        const char* exceptionName = "UNKNOWN";
        
        switch (exInfo->code) {
            case EXCEPTION_ACCESS_VIOLATION:
                exceptionName = "ACCESS_VIOLATION";
                break;
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
                exceptionName = "ARRAY_BOUNDS_EXCEEDED";
                break;
            case EXCEPTION_DATATYPE_MISALIGNMENT:
                exceptionName = "DATATYPE_MISALIGNMENT";
                break;
            case EXCEPTION_FLT_DENORMAL_OPERAND:
                exceptionName = "FLT_DENORMAL_OPERAND";
                break;
            case EXCEPTION_FLT_DIVIDE_BY_ZERO:
                exceptionName = "FLT_DIVIDE_BY_ZERO";
                break;
            case EXCEPTION_ILLEGAL_INSTRUCTION:
                exceptionName = "ILLEGAL_INSTRUCTION";
                break;
            case EXCEPTION_IN_PAGE_ERROR:
                exceptionName = "IN_PAGE_ERROR";
                break;
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
                exceptionName = "INT_DIVIDE_BY_ZERO";
                break;
            case EXCEPTION_INVALID_DISPOSITION:
                exceptionName = "INVALID_DISPOSITION";
                break;
            case EXCEPTION_STACK_OVERFLOW:
                exceptionName = "STACK_OVERFLOW";
                break;
        }
        
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        int len;
        if (exInfo->code == EXCEPTION_ACCESS_VIOLATION) {
            const char* operation = (exInfo->info0 == 0) ? "READ" : 
                                   (exInfo->info0 == 1) ? "write" : 
                                   (exInfo->info0 == 8) ? "execute" : "unknown";
            len = wsprintfA(buffer, 
                "[%04d-%02d-%02d %02d:%02d:%02d] %s: %s (0x%08X) at 0x%p - %s access to 0x%p\r\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                location, exceptionName, exInfo->code, exInfo->address, 
                operation, (LPVOID)exInfo->info1);
        } else {
            len = wsprintfA(buffer, 
                "[%04d-%02d-%02d %02d:%02d:%02d] %s: %s (0x%08X) at 0x%p - info[0]=0x%p, info[1]=0x%p\r\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                location, exceptionName, exInfo->code, exInfo->address,
                (LPVOID)exInfo->info0, (LPVOID)exInfo->info1);
        }
        
        DWORD written;
        WriteFile(hFile, buffer, len, &written, NULL);
        CloseHandle(hFile);
    }
}

// Utility functions
bool IsValidReadPtr(LPVOID ptr, SIZE_T size) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ptr, &mbi, sizeof(mbi))) {
        return (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY)) != 0;
    }
    return FALSE;
}

// Hook endpoints
VOID MickeyWonderPartner2Endpoint(LPVOID mickey, LPVOID house, LPVOID spell) {
    BOOL bFound = FALSE;
    
    Il2CppString* pString = originals.MickeyWonderPartner(minnie_buffer);
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
    if (!touch_screen_initialized && pEnvironment->UsingTouchScreen) {
        touch_screen_initialized = TRUE;
        ExceptionInfo exInfo = {0};
        
        __try {
            originals.SwitchInputDeviceToTouchScreen(NULL);
        } __except (exInfo.code = GetExceptionCode(),
                   exInfo.address = GetExceptionInformation()->ExceptionRecord->ExceptionAddress,
                   exInfo.info0 = GetExceptionInformation()->ExceptionRecord->NumberParameters > 0 ? 
                                 GetExceptionInformation()->ExceptionRecord->ExceptionInformation[0] : 0,
                   exInfo.info1 = GetExceptionInformation()->ExceptionRecord->NumberParameters > 1 ? 
                                 GetExceptionInformation()->ExceptionRecord->ExceptionInformation[1] : 0,
                   EXCEPTION_EXECUTE_HANDLER) {
            LogException("SetFieldOfViewEndpoint::SwitchInputDeviceToTouchScreen", &exInfo);
        }
    }
    
    if (pEnvironment->EnableSetTargetFrameRate) {
        originals.SetTargetFrameRate(pEnvironment->TargetFrameRate);
    }
    
    if (!pEnvironment->EnableSetFieldOfView) {
        return originals.SetFieldOfView(pThis, value);
    }
    
    if ((float)floor(value) <= 30.0f) {
        originals.SetEnableFogRendering(FALSE);
        originals.SetFieldOfView(pThis, pEnvironment->FixLowFovScene ? value : pEnvironment->FieldOfView);
    } else {
        originals.SetEnableFogRendering(!pEnvironment->DisableFog);
        originals.SetFieldOfView(pThis, pEnvironment->FieldOfView);
    }
}

VOID OpenTeamEndpoint() {
    if (pEnvironment->RemoveOpenTeamProgress && originals.CheckCanEnter()) {
        originals.OpenTeamPageAccordingly(FALSE);
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
            originals.SetActive(banner, FALSE);
        }
    }
}

bool EventCameraMoveEndpoint(LPVOID pThis, LPVOID event) {
    if (pEnvironment->DisableEventCameraMove) {
        return TRUE;
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

bool InstallMinHooks(UINT64 base, IslandEnvironment* env) {
    if (MH_Initialize() != MH_OK) {
        return FALSE;
    }

    LPVOID pTarget;
    MH_STATUS status;

    pTarget = (LPVOID)(base + env->FunctionOffsets.MickeyWonderPartner2);
    status = MH_CreateHook(pTarget, MickeyWonderPartner2Endpoint, (LPVOID*)&originals.MickeyWonderPartner2);
    if (status != MH_OK) return FALSE;

    pTarget = (LPVOID)(base + env->FunctionOffsets.SetFieldOfView);
    status = MH_CreateHook(pTarget, SetFieldOfViewEndpoint, (LPVOID*)&originals.SetFieldOfView);
    if (status != MH_OK) return FALSE;

    pTarget = (LPVOID)(base + env->FunctionOffsets.OpenTeam);
    status = MH_CreateHook(pTarget, OpenTeamEndpoint, (LPVOID*)&originals.OpenTeam);
    if (status != MH_OK) return FALSE;

    pTarget = (LPVOID)(base + env->FunctionOffsets.SetupQuestBanner);
    status = MH_CreateHook(pTarget, SetupQuestBannerEndpoint, (LPVOID*)&originals.SetupQuestBanner);
    if (status != MH_OK) return FALSE;

    pTarget = (LPVOID)(base + env->FunctionOffsets.EventCameraMove);
    status = MH_CreateHook(pTarget, EventCameraMoveEndpoint, (LPVOID*)&originals.EventCameraMove);
    if (status != MH_OK) return FALSE;

    pTarget = (LPVOID)(base + env->FunctionOffsets.ShowOneDamageTextEx);
    status = MH_CreateHook(pTarget, ShowOneDamageTextExEndpoint, (LPVOID*)&originals.ShowOneDamageTextEx);
    if (status != MH_OK) return FALSE;

    pTarget = (LPVOID)(base + env->FunctionOffsets.MickeyWonderCombineEntry);
    status = MH_CreateHook(pTarget, MickeyWonderCombineEntryEndpoint, (LPVOID*)&originals.MickeyWonderCombineEntry);
    if (status != MH_OK) return FALSE;

    originals.MickeyWonder = (MickeyWonderMethod)(base + env->FunctionOffsets.MickeyWonder);
    originals.MickeyWonderPartner = (MickeyWonderMethodPartner)(base + env->FunctionOffsets.MickeyWonderPartner);
    originals.SetEnableFogRendering = (SetEnableFogRenderingMethod)(base + env->FunctionOffsets.SetEnableFogRendering);
    originals.SetTargetFrameRate = (SetTargetFrameRateMethod)(base + env->FunctionOffsets.SetTargetFrameRate);
    originals.OpenTeamPageAccordingly = (OpenTeamPageAccordinglyMethod)(base + env->FunctionOffsets.OpenTeamPageAccordingly);
    originals.CheckCanEnter = (CheckCanEnterMethod)(base + env->FunctionOffsets.CheckCanEnter);
    originals.FindGameObject = (FindGameObjectMethod)(base + env->FunctionOffsets.FindGameObject);
    originals.SetActive = (SetActiveMethod)(base + env->FunctionOffsets.SetActive);
    originals.SwitchInputDeviceToTouchScreen = (SwitchInputDeviceToTouchScreenMethod)(base + env->FunctionOffsets.SwitchInputDeviceToTouchScreen);
    originals.MickeyWonderCombineEntryPartner = (MickeyWonderCombineEntryMethodPartner)(base + env->FunctionOffsets.MickeyWonderCombineEntryPartner);

    status = MH_EnableHook(MH_ALL_HOOKS);
    if (status != MH_OK) {
        MH_Uninitialize();
        return FALSE;
    }

    return TRUE;
}

// Hook procedure for exports
static LRESULT WINAPI IslandGetWindowHookImpl(int code, WPARAM wParam, LPARAM lParam) {
    return CallNextHookEx(NULL, code, wParam, lParam);
}

// Main DLL thread
DWORD WINAPI IslandThread(LPVOID lpParam) {
    HANDLE hFile = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, ISLAND_ENVIRONMENT_NAME);
    if (!hFile) {
        return GetLastError();
    }
    
    LPVOID lpView = MapViewOfFile(hFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (!lpView) {
        CloseHandle(hFile);
        return GetLastError();
    }
    
    pEnvironment = (IslandEnvironment*)lpView;
    pEnvironment->State = Started;
    
    UINT64 base = (UINT64)GetModuleHandleA(NULL);
    
    minnie_length = 0;
    for (INT32 n = 0; n < 3; n++) {
        MickeyWonderMethod mickeyWonder = (MickeyWonderMethod)(base + pEnvironment->FunctionOffsets.MickeyWonder);
        ExceptionInfo exInfo = {0};
        __try {
            Il2CppArraySize* result = mickeyWonder(n);
            if (result && minnie_length + result->max_length < sizeof(minnie_buffer)) {
                memcpy(minnie_buffer + minnie_length, &result->vector[0], result->max_length);
                minnie_length += (int)result->max_length;
            }
        } __except (exInfo.code = GetExceptionCode(),
                   exInfo.address = GetExceptionInformation()->ExceptionRecord->ExceptionAddress,
                   exInfo.info0 = GetExceptionInformation()->ExceptionRecord->NumberParameters > 0 ? 
                                 GetExceptionInformation()->ExceptionRecord->ExceptionInformation[0] : 0,
                   exInfo.info1 = GetExceptionInformation()->ExceptionRecord->NumberParameters > 1 ? 
                                 GetExceptionInformation()->ExceptionRecord->ExceptionInformation[1] : 0,
                   EXCEPTION_EXECUTE_HANDLER) {
            
            HANDLE hLogFile = CreateFileA("hutao_exceptions.log", 
                GENERIC_WRITE, FILE_SHARE_READ, NULL, 
                OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            
            if (hLogFile != INVALID_HANDLE_VALUE) {
                SetFilePointer(hLogFile, 0, NULL, FILE_END);
                
                char debugBuffer[512];
                SYSTEMTIME st;
                GetLocalTime(&st);
                
                const char* operation = (exInfo.info0 == 0) ? "read" : 
                                       (exInfo.info0 == 1) ? "write" : 
                                       (exInfo.info0 == 8) ? "execute" : "unknown";
                
                int len = wsprintfA(debugBuffer, 
                    "[%04d-%02d-%02d %02d:%02d:%02d] MickeyWonder[%d] ACCESS_VIOLATION:\r\n"
                    "  Base: %p\r\n"
                    "  Offset: %u (0x%08X)\r\n"
                    "  Calculated: %p\r\n"
                    "  Exception at: %p - %s access to %p\r\n\r\n",
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                    n,
                    (void*)base,
                    pEnvironment->FunctionOffsets.MickeyWonder,
                    pEnvironment->FunctionOffsets.MickeyWonder,
                    (void*)(base + pEnvironment->FunctionOffsets.MickeyWonder),
                    exInfo.address,
                    operation,
                    (LPVOID)exInfo.info1);
                
                DWORD written;
                WriteFile(hLogFile, debugBuffer, len, &written, NULL);
                CloseHandle(hLogFile);
            }
        }
    }
    
    if (!InstallMinHooks(base, pEnvironment)) {
        pEnvironment->State = Error;
        pEnvironment->LastError = GetLastError();
        UnmapViewOfFile(lpView);
        CloseHandle(hFile);
        return GetLastError();
    }
    
    WaitForSingleObject(GetCurrentThread(), INFINITE);
    
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    
    pEnvironment->State = Stopped;
    UnmapViewOfFile(lpView);
    CloseHandle(hFile);
    
    FreeLibraryAndExitThread((HMODULE)lpParam, 0);
    return 0;
}

// Export functions - Updated following upstream changes
extern "C" {
    __declspec(dllexport) HRESULT WINAPI DllGetWindowsHookForHutao(HOOKPROC* pHookProc) {
        // We don't handle package family checks - keep it simple
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
        LdrAddRefDll(LDR_ADDREF_DLL_PIN, hModule);
        DisableProtectVirtualMemory();
        CreateThread(NULL, 0, IslandThread, hModule, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        Sleep(500);
        break;
    }
    return TRUE;
}