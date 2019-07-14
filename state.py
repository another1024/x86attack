from tools import *
from pwn import *
from config import register
class state():
	def __init__(self, binary, crash):
		self.binary = binary
		self.crash = crash
		self.info = {}
		self.tools = tools(binary, crash)

	def get_register_info(self):
		self.register_string = self.tools.gdb('info register')
		for i in register:
			self.info[i] = p32(int(self.register_string.split(i)[1].lstrip().split('\t')[0],16))
			t='data_in_'+i
			self.info[t] = self.tools.get_data(0x100, u32(self.info[i]))
        

	def get_segment_data(self):
		elf = ELF(self.binary)
		self.info['bss_addr'] = str(elf.bss(0))
		self.info['bss_data'] = self.tools.get_data(0x1000, int(self.info['bss_addr']))
	def getinfo(self):
		return self.info

