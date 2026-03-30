/*
 * kill_smb.c - 停止SMB服务释放445端口 (for ntlmrelayx)
 * Compile: x86_64-w64-mingw32-gcc -o kill_smb.exe kill_smb.c -liphlpapi -lpsapi -lws2_32
 * Usage: kill_smb.exe
 */

#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <psapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ws2_32.lib")

// 获取占用指定端口的进程PID
DWORD GetPidByPort(USHORT port) {
    PMIB_TCPTABLE_OWNER_PID pTcpTable = NULL;
    ULONG size = 0;
    DWORD pid = 0;

    GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (pTcpTable == NULL) {
        return 0;
    }

    if (GetExtendedTcpTable(pTcpTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            if (ntohs((USHORT)pTcpTable->table[i].dwLocalPort) == port) {
                pid = pTcpTable->table[i].dwOwningPid;
                break;
            }
        }
    }

    free(pTcpTable);
    return pid;
}

// 检查端口是否被占用
BOOL IsPortInUse(USHORT port) {
    return GetPidByPort(port) != 0;
}

// 启用SeDebugPrivilege
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL);
    CloseHandle(hToken);
    return result && (GetLastError() == ERROR_SUCCESS);
}

// 执行命令并等待
BOOL RunCommand(const char* cmd) {
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    char cmdline[512];
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /c %s", cmd);

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return FALSE;
    }

    WaitForSingleObject(pi.hProcess, 30000);  // 30秒超时

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return exitCode == 0;
}

// 停止SMB服务
BOOL StopSMBService() {
    printf("[*] Stopping SMB services...\n");

    // 停止主要SMB服务
    printf("    [-] Stopping lanmanserver...\n");
    RunCommand("net stop lanmanserver /y");

    printf("    [-] Stopping smb...\n");
    RunCommand("net stop smb /y");

    printf("    [-] Stopping LanmanWorkstation...\n");
    RunCommand("net stop LanmanWorkstation /y");

    Sleep(1000);
    return TRUE;
}

// 禁用SMB驱动
BOOL DisableSMBDrivers() {
    printf("[*] Disabling SMB drivers...\n");

    // 禁用SRV2驱动 (SMB 2.0)
    printf("    [-] Stopping srv2...\n");
    RunCommand("sc stop srv2");

    // 禁用SRV驱动 (SMB 1.0)
    printf("    [-] Stopping srv...\n");
    RunCommand("sc stop srv");

    // 禁用srvnet
    printf("    [-] Stopping srvnet...\n");
    RunCommand("sc stop srvnet");

    Sleep(2000);
    return TRUE;
}

// 设置SMB服务为禁用
BOOL DisableSMBStartup() {
    printf("[*] Setting SMB services to disabled...\n");

    RunCommand("sc config lanmanserver start= disabled");
    RunCommand("sc config srv2 start= disabled");
    RunCommand("sc config srv start= disabled");

    return TRUE;
}

// 强制关闭445端口监听
void ForceClosePort445() {
    printf("[*] Additional steps to free port 445...\n");

    // 通过注册表禁用SMB
    printf("    [-] Modifying registry...\n");
    RunCommand("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v SMB1 /t REG_DWORD /d 0 /f");
    RunCommand("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v SMB2 /t REG_DWORD /d 0 /f");

    // 禁用TCP上的SMB
    printf("    [-] Disabling SMB over TCP...\n");
    RunCommand("sc config lanmanserver depend= /");
}

int main() {
    printf("\n");
    printf("====================================================\n");
    printf("  kill_smb - Free port 445 for ntlmrelayx\n");
    printf("====================================================\n\n");

    // 检查是否以管理员运行
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    if (!isAdmin) {
        printf("[!] WARNING: Not running as Administrator!\n");
        printf("[!] Some operations may fail.\n\n");
    }

    // 启用调试权限
    if (EnableDebugPrivilege()) {
        printf("[+] SeDebugPrivilege enabled\n");
    }

    // 检查当前445端口状态
    printf("\n[*] Checking port 445 status...\n");
    if (!IsPortInUse(445)) {
        printf("[+] Port 445 is already FREE!\n");
        printf("[+] You can now run ntlmrelayx.py\n");
        return 0;
    }

    DWORD pid = GetPidByPort(445);
    printf("[!] Port 445 is in use by PID: %d\n\n", pid);

    // 步骤1: 停止SMB服务
    StopSMBService();

    // 检查端口
    if (!IsPortInUse(445)) {
        printf("\n[+] SUCCESS! Port 445 is now FREE!\n");
        printf("[+] You can now run: ntlmrelayx.py -tf targets.txt\n");
        return 0;
    }

    // 步骤2: 禁用SMB驱动
    DisableSMBDrivers();

    // 检查端口
    if (!IsPortInUse(445)) {
        printf("\n[+] SUCCESS! Port 445 is now FREE!\n");
        printf("[+] You can now run: ntlmrelayx.py -tf targets.txt\n");
        return 0;
    }

    // 步骤3: 额外措施
    ForceClosePort445();
    DisableSMBStartup();

    // 最终检查
    Sleep(2000);
    printf("\n[*] Final port check...\n");

    if (!IsPortInUse(445)) {
        printf("[+] SUCCESS! Port 445 is now FREE!\n");
        printf("\n[!] NOTE: You may need to restart Windows for changes to take full effect.\n");
    } else {
        pid = GetPidByPort(445);
        printf("[-] Port 445 is STILL in use by PID: %d\n", pid);
        printf("\n[!] Manual steps:\n");
        printf("    1. Open Services (services.msc)\n");
        printf("    2. Stop and disable 'Server' service\n");
        printf("    3. Reboot if necessary\n");
        printf("    4. Or run: REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v SMB1 /t REG_DWORD /d 1 /f\n");
        printf("    5. And run: REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v SMB2 /t REG_DWORD /d 0 /f\n");
    }

    printf("\n====================================================\n");
    return 0;
}
