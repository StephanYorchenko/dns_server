class DNSHeaderFlags:
	def __init__(self, data=b''):
		self.data = int.from_bytes(data, 'big')
		self.qr = self.get_bit_slice(0, 0, self.data)
		self.opcode = self.get_bit_slice(1, 4, self.data)
		self.aa = self.get_bit_slice(5, 5, self.data)
		self.tc = self.get_bit_slice(6, 6, self.data)
		self.rd = self.get_bit_slice(7, 7, self.data)
		self.ra = self.get_bit_slice(8, 8, self.data)
		self.z = self.get_bit_slice(9, 10, self.data)
		self.rcode = self.get_bit_slice(11, 15, self.data)

	@staticmethod
	def get_bit_slice(start, end, number):
		return ((number << start) & 0xFFFF) >> (start + 16 - end - 1)

	@classmethod
	def generate_flags(
			cls, qa=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, r_code=0):
		flag = 1
		flag = flag << 1 | qa
		flag = flag << 4 | opcode
		flag = flag << 1 | aa
		flag = flag << 1 | tc
		flag = flag << 1 | rd
		flag = flag << 1 | ra
		flag = flag << 3 | z
		flag = flag << 4 | r_code

		return DNSHeaderFlags((flag & 0xFFFF).to_bytes(2, 'big'))

	def to_bytes(self):
		return self.data.to_bytes(2, 'big')
