from ctypes import *
from ctypes.wintypes import *
import subprocess
import csv
import binascii

#This needs to be our target string bitwise xored with the letter A, converted to hex.
strtofind = "3235252031281e3238321e31332e222432321e262435312825"

class MEMORY_BASIC_INFORMATION (Structure):
    _fields_ = [
        ("BaseAddress",  c_ulong),
        ("AllocationBase", c_ulong),
        ("AllocationProtect", c_long),
        ("RegionSize", c_long),
        ("State", c_long),
        ("Protect", c_long),
        ("Type", c_long)]


class TOKEN_PRIVS(Structure):
    _fields_ = [
        ('PrivilegeCount', ULONG),
        ('Privileges', ULONG * 3)
    ]


class MemTypes:
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_GUARD = 0x100
    WRITABLE = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_GUARD
    MEM_COMMIT = 0x1000


#Thanks to jyk95 at waitfordebug.wordpress.com
def GetDebugPrivileges():
    proctoken = HANDLE()
    windll.advapi32.OpenProcessToken(
        windll.kernel32.GetCurrentProcess(), 0x00000020, byref(proctoken))
    privs = c_ulong()
    windll.advapi32.LookupPrivilegeValueA(None, "SeDebugPrivilege", byref(privs))
    newprivs = TOKEN_PRIVS()
    newprivs.PrivilegeCount = 1
    newprivs.Privileges = (privs.value, 0, 2)
    windll.advapi32.AdjustTokenPrivileges(proctoken, 0, byref(newprivs), 0, 0, 0)
    windll.kernel32.CloseHandle(proctoken)

#Xors arbitrary hex data bitwise with the letter A. This helps prevent false positives
def xordata(data):
    return binascii.hexlify(''.join(chr(ord(x) ^ ord('A')) for x in data.decode('hex')))

OpenProcess = windll.kernel32.OpenProcess
ReadProcessMemory = windll.kernel32.ReadProcessMemory
CloseHandle = windll.kernel32.CloseHandle
VirtualQueryEx = windll.kernel32.VirtualQueryEx

PROCESS_ALL_ACCESS = 0x1F0FFF

GetDebugPrivileges()

data = subprocess.check_output(["tasklist", "/fo", "csv"]).splitlines()
processess = csv.DictReader(data)
for row in processess:
    pid = int(row['PID'])
    memlist = []
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    x = MemTypes()
    address = 0
    while (1 == 1):
        MemInfo = MEMORY_BASIC_INFORMATION()
        size = c_int(sizeof(MemInfo))
        MemDump = VirtualQueryEx(processHandle, address, byref(MemInfo), size)
        if (MemDump == 0):
            break
        if (0 != (MemInfo.State & x.MEM_COMMIT) and 0 != (MemInfo.Protect & x.WRITABLE) and 0 == (MemInfo.Protect & x.PAGE_GUARD)):
            memlist.append(MemInfo)
        address = c_long(MemInfo.BaseAddress + MemInfo.RegionSize)

    for x in memlist:
        gen = ('a') * x.RegionSize
        buffer = c_char_p(gen)
        address = c_long(x.BaseAddress)
        bytesRead = c_ulong(0)
        ReadProcessMemory(processHandle, address, buffer, len(buffer.value), bytesRead)
        hexencoded = binascii.hexlify(buffer.value)
        hexencoded = xordata(hexencoded)
        if (strtofind in hexencoded):
            print(xordata(strtofind).decode('hex') + " found in " + row['Image Name'])

    CloseHandle(processHandle)
