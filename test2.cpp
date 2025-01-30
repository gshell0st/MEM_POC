#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

// Converte WCHAR* para std::string
std::string WideCharToString(const WCHAR* wstr) {
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &str[0], size_needed, NULL, NULL);
    return str;
}

// Obtém o PID de um processo pelo nome
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
    const char* processName = "notepad.exe";  // Nome do processo alvo
    DWORD processID = GetProcessID(processName);

    if (!processID) {
        std::cerr << "Processo não encontrado!" << std::endl;
        return 1;
    }

    // Abre o processo com permissões totais
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::cerr << "Erro ao abrir processo: " << GetLastError() << std::endl;
        return 1;
    }

    // Aloca memória no processo remoto
    LPVOID allocMem = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!allocMem) {
        std::cerr << "Falha ao alocar memória no processo!" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Código de shellcode (exemplo: NOPs)
    BYTE shellcode[] = { 0x90, 0x90, 0x90 };

    // Escreve o shellcode na memória do processo remoto
    if (!WriteProcessMemory(hProcess, allocMem, shellcode, sizeof(shellcode), NULL)) {
        std::cerr << "Erro ao escrever na memória do processo!" << std::endl;
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "Memória do processo modificada com sucesso!" << std::endl;

    // Libera a memória alocada e fecha o handle do processo
    VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}