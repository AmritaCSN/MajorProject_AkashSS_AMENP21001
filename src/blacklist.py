#Most common DLLs where a code injeciton of fileless malware takes place on the memory.

FILELESS_MALWARE_DLLS = [
    'ntdll.dll',
    'kernel32.dll',
    'advapi32.dll',
    'user32.dll',
    'ws2_32.dll',
    'wininet.dll',
]

MALWARE_DLLS = [
    'kernel32.dll',
    'user32.dll',
    'shell32.dll',
    'ws2_32.dll',
    'wininet.dll',
    'advapi32.dll',
    'crypt32.dll',
    'gdi32.dll',
    'ntdll.dll',
    'secur32.dll',
    'shlwapi.dll',
    'urlmon.dll',
    'winhttp.dll',
    'wsock32.dll',
    'ntoskrnl.exe',
    'hal.dll',
    'bootvid.dll',
    'kdcom.dll',
    'cng.sys',
    'halacpi.dll',
    'halaacpi.dll',
    'halapic.dll',
    'halmps.dll',
    'halsp.dll',
    'kd.dll',
    'kdstub.dll',
    'msrpc.sys',
    'ndis.sys',
    'ntoskrnl.exe',
    'srv.sys',
    'srv2.sys',
    'srvnet.sys',
]

def islisted(x):
    if(x in FILELESS_MALWARE_DLLS or x in MALWARE_DLLS):
        return True
    else:
        return False