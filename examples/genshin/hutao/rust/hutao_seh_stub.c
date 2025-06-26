// hutao_seh_stub.c
#include <stdint.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define MS_SUCCEEDED 0x0
#define MS_CATCHED 0x1

typedef void(CALLBACK *PPROC_EXECUTOR)(PVOID Proc);

typedef struct _EXCEPTION
{
    DWORD Code;
    PVOID Address;
} EXCEPTION, *PEXCEPTION;

uint32_t __hutao_seh_HandlerStub(
    _In_ PPROC_EXECUTOR ProcExecutor,
    _In_ PVOID Proc,
    _Inout_ PEXCEPTION Exception
) {
    uint32_t Result = MS_SUCCEEDED;
    DWORD Code = 0;
    LPEXCEPTION_POINTERS Pointers = NULL;

    __try
    {
        ProcExecutor(Proc);
    }
    __except (Code = GetExceptionCode(), Pointers = GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER)
    {
        Result = MS_CATCHED;
        if (Exception != NULL)
        {
            // Use GetExceptionCode() instead of Record->ExceptionCode as it is more reliable.
            Exception->Code = Code;
            Exception->Address = Pointers->ExceptionRecord->ExceptionAddress;
        }
    }

    return Result;
}