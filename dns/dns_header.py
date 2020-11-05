from dns.dns_header_flasgs import DNSHeaderFlags


class DNSHeader:
	def __init__(self, data=None):
		if data is not None:
			self.id = int.from_bytes(data[:2], 'big')
			self.flags = DNSHeaderFlags(data[2:4])
			self.qd_count = int.from_bytes(data[4:6], 'big')
			self.ans_count = int.from_bytes(data[6:8], 'big')
			self.ns_count = int.from_bytes(data[8:10], 'big')
			self.ar_count = int.from_bytes(data[10:12], 'big')