from dns.dns_base import Types, Classes


class DNSQuestion:
	def __init__(self, qname=b'', query_type=Types['A'], query_class=Classes['IN']):
		self.qname = qname
		self.type = query_type
		self.class_ = query_class

	def to_bytes(self):
		q_name = self.qname
		if not q_name.endswith(b'.'):
			q_name += b'.'
		q_name = b''.join(
			map(lambda x: len(x).to_bytes(1, 'big') + x, q_name.split(b'.')))
		q_type = self.type.to_bytes(2, 'big')
		q_class = self.class_.to_bytes(2, 'big')

		return q_name + q_type + q_class
