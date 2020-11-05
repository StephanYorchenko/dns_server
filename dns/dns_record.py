from dns.dns_base import Types, Classes


class DNSResourceRecord:
	def __init__(self,
				 qname=b'',
				 record_type=Types['A'],
				 record_class=Classes['IN'],
				 ttl=3600,
				 data=b''):
		self.qname = qname
		self.type = record_type
		self.class_ = record_class
		self.ttl = ttl
		self.data = data

	def to_bytes(self):
		qname = self.qname
		if not qname.endswith(b'.'):
			qname += b'.'
		q_name = b''.join(
				map(lambda x: len(x).to_bytes(1, 'big') + x,
					qname.split(b'.')))
		r_type = self.type.to_bytes(2, 'big')
		r_class = self.class_.to_bytes(2, 'big')
		ttl = self.ttl.to_bytes(4, 'big')
		rd_length = len(self.data).to_bytes(2, 'big')

		return q_name + r_type + r_class + ttl + rd_length + self.data
