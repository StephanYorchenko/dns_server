class DNSCreator:
	def __init__(self,
				 requests=None,
				 answers=None,
				 authorities=None,
				 additional=None,
				 flags=b'\xff\xff',
				 id=5639):
		self.requests = requests or []
		self.answers = answers or []
		self.authorities = authorities or []
		self.additional = additional or []
		self.flags = flags
		self.id = id

	def create(self):
		result = b''
		result += self.id.to_bytes(2, 'big') + self.flags \
                  + len(self.requests).to_bytes(2, 'big') \
                  + len(self.answers).to_bytes(2, 'big') \
                  + len(self.authorities).to_bytes(2, 'big') \
                  + len(self.additional).to_bytes(2, 'big')

		result += b''.join(map(lambda req: req.to_bytes(), self.requests))
		result += b''.join(map(lambda x: x.to_bytes(), self.answers))
		result += b''.join(map(lambda x: x.to_bytes(), self.authorities))
		result += b''.join(map(lambda x: x.to_bytes(), self.additional))

		return result
