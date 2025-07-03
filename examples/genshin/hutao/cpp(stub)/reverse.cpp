void DllInjectionUtilitiesInjectUsingWindowsHook(LPCWSTR param_1,LPCWSTR param_2,undefined4 param_3)

{
    ulonglong uVar1;
    code *pcVar2;
    undefined auVar3 [16];
    undefined8 uVar4;
    int iVar5;
    DWORD dwThreadId;
    BOOL BVar6;
    HMODULE hModule;
    ulonglong uVar7;
    ulonglong uVar8;
    void *pvVar9;
    LPSTR lpMultiByteStr;
    char *pcVar10;
    FARPROC pFVar11;
    INT_PTR IVar12;
    HWND *lParam;
    HHOOK pHVar13;
    uint uVar14;
    LPCSTR lpProcName;
    void *pvVar15;
    char *pcVar16;
    ulonglong _Size;
    undefined8 unaff_retaddr;
    undefined auStackY_b8 [32];
    longlong local_78;
    HOOKPROC local_70;
    undefined local_68 [8];
    undefined8 uStack_60;
    ulonglong local_58;
    ulonglong local_50;
    ulonglong local_48;

    /* 0x4770  1  DllInjectionUtilitiesInjectUsingWindowsHook */
    local_48 = DAT_18002d040 ^ (ulonglong)auStackY_b8;
    hModule = LoadLibraryExW(param_1,(HANDLE)0x0,8);
    if (hModule == (HMODULE)0x0) {
        FUN_180003400(unaff_retaddr,0x30,
                      "D:\\a\\Snap.Hutao.Native\\Snap.Hutao.Native\\Snap.Hutao.Native\\DllInjectionUtili ties.cpp"
                      ,"DllInjectionUtilitiesInjectUsingWindowsHook","hModule",0x18001b580);
        goto LAB_180004b85;
    }
    pvVar15 = (void *)0x0;
    iVar5 = WideCharToMultiByte(0xfde9,0,param_2,-1,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
    _Size = (ulonglong)iVar5;
    _local_68 = ZEXT816(0);
    if (0x7fffffffffffffff < _Size) {
        FUN_1800045f0();
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return;
    }
    if (_Size < 0x10) {
        local_50 = 0xf;
        local_58 = _Size;
        memset(local_68,0,_Size);
        local_68[_Size] = 0;
    }
    else {
        uVar7 = _Size | 0xf;
        if (uVar7 < 0x8000000000000000) {
            if (uVar7 < 0x16) {
                uVar7 = 0x16;
            }
            uVar1 = uVar7 + 1;
            uVar4 = 0;
            if (uVar1 != 0) {
                if (0xfff < uVar1) {
                    uVar8 = uVar7 + 0x28;
                    if (uVar8 <= uVar1) {
                        FUN_180004550();
                        pcVar2 = (code *)swi(3);
                        (*pcVar2)();
                        return;
                    }
                    goto LAB_180004883;
                }
                pvVar15 = operator_new(uVar1);
                uVar4 = uStack_60;
            }
        }
        else {
            uVar8 = 0x8000000000000027;
            uVar7 = 0x7fffffffffffffff;
            LAB_180004883:
            pvVar9 = operator_new(uVar8);
            if (pvVar9 == (void *)0x0) goto LAB_180004b60;
            pvVar15 = (void *)((longlong)pvVar9 + 0x27U & 0xffffffffffffffe0);
            *(void **)((longlong)pvVar15 - 8) = pvVar9;
            uVar4 = uStack_60;
        }
        uStack_60 = uVar4;
        local_68 = (undefined  [8])pvVar15;
        local_58 = _Size;
        local_50 = uVar7;
        memset(pvVar15,0,_Size);
        *(undefined *)((longlong)pvVar15 + _Size) = 0;
    }
    lpMultiByteStr = local_68;
    if (0xf < local_50) {
        lpMultiByteStr = (LPSTR)local_68;
    }
    iVar5 = WideCharToMultiByte(0xfde9,0,param_2,-1,lpMultiByteStr,iVar5,(LPCSTR)0x0,(LPBOOL)0x0);
    if (iVar5 == 0) {
        uVar14 = 0x34;
        pcVar10 =
        "0 == WideCharToMultiByte(CP_UTF8, 0, functionName, -1, functionNameA.data(), size, NULL, NULL)"
        ;
        pcVar16 = "Failed to convert functionName to PCSTR";
        LAB_18000497b:
        FUN_180003400(unaff_retaddr,uVar14,
                      "D:\\a\\Snap.Hutao.Native\\Snap.Hutao.Native\\Snap.Hutao.Native\\DllInjectionUtili ties.cpp"
                      ,"DllInjectionUtilitiesInjectUsingWindowsHook",pcVar10,(longlong)pcVar16);
    }
    else {
        lpProcName = local_68;
        if (0xf < local_50) {
            lpProcName = (LPCSTR)local_68;
        }
        pFVar11 = GetProcAddress(hModule,lpProcName);
        if (pFVar11 == (FARPROC)0x0) {
            uVar14 = 0x37;
            pcVar10 = "getWindowsHook";
            pcVar16 = "Failed to get target function from dll\'s EAT";
            goto LAB_18000497b;
        }
        IVar12 = (*pFVar11)(&local_70);
        if ((int)(uint)IVar12 < 0) {
            FUN_1800033b0(unaff_retaddr,0x3a,
                          "D:\\a\\Snap.Hutao.Native\\Snap.Hutao.Native\\Snap.Hutao.Native\\DllInjectionUti lities.cpp"
                          ,"DllInjectionUtilitiesInjectUsingWindowsHook",
                          "reinterpret_cast<HRESULT(*)(HOOKPROC*)>(getWindowsHook)(&hookProc)",
                          (uint)IVar12,0x18001b700);
        }
        else {
            while( true ) {
                lParam = (HWND *)operator_new(0x10);
                *(undefined4 *)((longlong)lParam + 0xc) = 0;
                *lParam = (HWND)0x0;
                *(undefined4 *)(lParam + 1) = param_3;
                EnumWindows(FUN_1800046f0,(LPARAM)lParam);
                if (*lParam != (HWND)0x0) break;
                local_78 = 0x32;
                FUN_180005940(&local_78);
            }
            dwThreadId = GetWindowThreadProcessId(*lParam,(LPDWORD)0x0);
            if (dwThreadId == 0) {
                FUN_180003400(unaff_retaddr,0x4a,
                              "D:\\a\\Snap.Hutao.Native\\Snap.Hutao.Native\\Snap.Hutao.Native\\DllInjectionU tilities.cpp"
                              ,"DllInjectionUtilitiesInjectUsingWindowsHook","!threadId",0x18001b778);
            }
            else {
                pHVar13 = SetWindowsHookExW(3,local_70,hModule,dwThreadId);
                if (pHVar13 == (HHOOK)0x0) {
                    FUN_180003400(unaff_retaddr,0x4d,
                                  "D:\\a\\Snap.Hutao.Native\\Snap.Hutao.Native\\Snap.Hutao.Native\\DllInjectio nUtilities.cpp"
                                  ,"DllInjectionUtilitiesInjectUsingWindowsHook","hHook",0x18001b7b8);
                }
                else {
                    BVar6 = PostThreadMessageW(dwThreadId,0,0,0);
                    if (BVar6 == 0) {
                        FUN_180003400(unaff_retaddr,0x4f,
                                      "D:\\a\\Snap.Hutao.Native\\Snap.Hutao.Native\\Snap.Hutao.Native\\DllInject ionUtilities.cpp"
                                      ,"DllInjectionUtilitiesInjectUsingWindowsHook",
                                      "PostThreadMessageW(threadId, WM_NULL, NULL, NULL)",0x18001b7f8);
                    }
                }
            }
        }
    }
    if (0xf < local_50) {
        pvVar15 = (void *)local_68;
        if ((0xfff < local_50 + 1) &&
            (pvVar15 = *(void **)((longlong)local_68 + -8),
             0x1f < (ulonglong)((longlong)local_68 + (-8 - (longlong)pvVar15)))) {
            LAB_180004b60:
            /* WARNING: Subroutine does not return */
            _invalid_parameter_noinfo_noreturn();
             }
             free(pvVar15);
    }
    local_58 = 0;
    local_50 = 0xf;
    auVar3[15] = 0;
    auVar3._0_15_ = stack0xffffffffffffff99;
    _local_68 = auVar3 << 8;
    FreeLibrary(hModule);
    LAB_180004b85:
    FUN_180016290(local_48 ^ (ulonglong)auStackY_b8);
    return;
}

