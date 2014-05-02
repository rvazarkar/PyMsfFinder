import binascii
strtoxor = "stdapi_sys_process_getpid"

print(binascii.hexlify("".join(chr(ord(x) ^ ord('A')) for x in strtoxor)))