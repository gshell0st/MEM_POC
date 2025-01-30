#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

// Caminho do executável alvo
const char* BINARIO_ALVO = "path\\to\\bin";

// Nome da DLL que será "comentada" (removida da lista de módulos)
const char* DLL_ALVO = "exemplo.dll";

// Converte WCHAR* para std::string
std::string WideCharToString(const WCHAR* wstr) {
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &str[0], size_needed, NULL, NULL);
    return str;
}

// Obtém o PID do processo recém-criado
DWORD GetProcessID(const char* processName) {
    DWORD processID = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            std::string exeFile = WideCharToString(entry.szExeFile);
            if (_stricmp(exeFile.c_str(), processName) == 0) {
                processID = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return processID;
}

int main() {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (!CreateProcessA(NULL, (LPSTR)BINARIO_ALVO, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "[X] Erro ao abrir o binario: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "[+] Binario aberto com PID: " << pi.dwProcessId << std::endl;
    CloseHandle(pi.hThread);

    Sleep(1000);

    DWORD processID = pi.dwProcessId;
    if (!processID) {
        std::cerr << "[X] Erro ao obter PID do processo!" << std::endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::cerr << "[X] Erro ao abrir processo: " << GetLastError() << std::endl;
        return 1;
    }

    // Shellcode para remover DLL da lista de módulos
    BYTE shellcode[] = {
        0x55,                               // push ebp
        0x89, 0xE5,                         // mov ebp, esp
        0x83, 0xEC, 0x08,                   // sub esp, 8
        0xE8, 0x00, 0x00, 0x00, 0x00,       // call next_instruction
        0x5B,                               // pop ebx (EBX agora contém o endereço do próximo byte)
        0x81, 0xEB, 0x05, 0x00, 0x00, 0x00, // sub ebx, 5 (Recuamos para encontrar o endereço da string)
        0x8D, 0x83, 0x00, 0x00, 0x00, 0x00, // lea eax, [ebx+offset]
        0x50,                               // push eax (endereço da string DLL)
        0xFF, 0xD0,                         // call EAX (chamada para função personalizada que remove a DLL)
        0x83, 0xC4, 0x08,                   // add esp, 8 (limpa a pilha)
        0xC9,                               // leave
        0xC3                                // ret
    };

    // Aloca memória no processo remoto para o shellcode
    LPVOID allocMem = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!allocMem) {
        std::cerr << "[X] Falha ao alocar memoria no processo!" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Escreve o shellcode na memória do processo remoto
    if (!WriteProcessMemory(hProcess, allocMem, shellcode, sizeof(shellcode), NULL)) {
        std::cerr << "[X] Erro ao escrever na memoria do processo!" << std::endl;
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Cria um thread remoto para executar o shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)allocMem, NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "[x] Erro ao criar thread remota!" << std::endl;
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "[+] Shellcode injetado e executado com sucesso!" << std::endl;

    WaitForSingleObject(hThread, INFINITE); // Aguarda a execução do shellcode
    CloseHandle(hThread);

    std::cout << "[!] Pressione Enter para encerrar o programa e manter o binario aberto [!]" << std::endl;
    std::cin.get();

    VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    CloseHandle(pi.hProcess);

    return 0;
}
