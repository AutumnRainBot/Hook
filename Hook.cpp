#include <windows.h>
#include <iostream>

HMODULE myhmod;

void EjectThread()
{
    FreeLibraryAndExitThread(myhmod, 0);
}

BOOL Hook(void* Address, void* OurFunction, int len)
{
    if (len >= 5) //make sure we can fit our hook at the Address where we want to hook (our hook = 1bytes jmp , + 4bytes address where to jump)
    {
        DWORD protection;//dword means its an address
        VirtualProtect(Address, len, PAGE_EXECUTE_READWRITE, &protection);//make it so we can read and write where the address is (Store the previous permission at the address of (protection)

        DWORD realtiveAddress = ((DWORD)OurFunction - (DWORD)Address) - 5;//find out how much we need to jmp by (End - Start) - (jmp size)

        *(BYTE*)Address = 0xE9; //Changing the value at the address we are hooking at , to make it a jmp instruction 0xDEADBEEF (dec [eax]) -> (jmp)
        *(DWORD*)((DWORD)Address + 1) = realtiveAddress; //Make it so : 0xDEADBEEF (dec [eax]) -> (jmp relativeAddress) so it jump to the address where our code will be

        //Restore protection
        DWORD temp;
        VirtualProtect(Address, len, protection, &temp);//make it so the new protection is the old protection we stored in the (protection) variable

        return true;
    }
    else
    {
        return false;
    }
}

DWORD jmpbk; // we need to jump back to where we hooked + 6; cuz 1(jmp) 4(address where we need to jump) 1(get the byte after it)

void* teax;
void* tebx;
void* tecx;
void* tedx;
void* tesi;
void* tedi;
void* tebp;
void* tesp;

__declspec(naked) void ourFunc()
{
    _asm
    {
        mov teax, eax; backup
        mov tebx, ebx
        mov tecx, ecx
        mov tedx, edx
        mov tesi, esi
        mov tedi, edi
        mov tebp, ebp
        mov tesp, esp
        //end of the backup register

        inc[eax] //incrementing the value stored in the register eax; [eax] means value at eax
        jmp[jmpbk]//jump back to the next instruction after where we hook to avoid crash
    }
}


void Main()
{
    //Print on screen function
    typedef void(__stdcall* prototype)(const char* Message, ...);
    prototype Print = reinterpret_cast<prototype>(0x4DAD50);
    

    int hooklength = 6;//2 bytes from the dec[eax] and 4 bytes at the next adress (we have to take the entire next like.
    DWORD hookaddress = 0x04C73EF;//Adress where the dec[eax] is
    jmpbk = hookaddress + hooklength;
    if (Hook((void*)hookaddress, ourFunc, hooklength))
    {
        MessageBoxA(0, "Successfully hooked ","Success",0);
        Print("Hooked dec[eax] -> inc[eax]");
    }
    else
    {
        MessageBoxA(0, "Failed to hook!", "Fail :c", 0);
    }


    while (true)
    {
        if (GetAsyncKeyState(VK_END))
        {
            break;
        }
        Sleep(100);
    }

    MessageBoxA(0, "UnInjecting", "Bye", 0);
    FreeLibraryAndExitThread((HMODULE)myhmod, 0);

}

BOOL APIENTRY DllMain( HMODULE hModule,DWORD  reason,LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        myhmod = hModule;
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Main, 0, 0, 0);
    }
    return TRUE;
}

