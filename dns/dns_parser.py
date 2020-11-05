from .dns_base import Types
from .dns_header import DNSHeader
from .dns_question import DNSQuestion
from .dns_record import DNSResourceRecord


class DNSPacket:
	def __init__(self, data: bytes):
		self._data = data
		pointer = 12
		self.header = DNSHeader(data[:pointer])
		*self.queries, pointer = self._parse_query(pointer, self.header.qd_count)
		self.answers, pointer = self._read_rrecords(self.header.ans_count, pointer)
		self.authority, pointer = self._read_rrecords(self.header.ns_count, pointer)
		self.additional, pointer = self._read_rrecords(self.header.ar_count, pointer)

	def _parse_query(self, start, count):
		index = start
		for _ in range(count):
			name, name_end = self._read_name(start)
			q_type = int.from_bytes(self._data[name_end:name_end + 2], 'big')
			q_class = int.from_bytes(self._data[name_end + 2:name_end + 4], 'big')
			yield DNSQuestion(name, q_type, q_class)
			index = name_end + 4
		yield index

	def _read_rrecords(self, count, start):
		index, result = start, []
		for i in range(count):
			parsed_obj, ind = self._parse_rrecord(index)
			result.append(parsed_obj)
			index = ind
		return result, index

	def _parse_rrecord(self, start):
		name, name_end = self._read_name(start)
		record_type = int.from_bytes(self._data[name_end:name_end + 2], 'big')
		record_class = int.from_bytes(self._data[name_end + 2:name_end + 4], 'big')
		ttl = int.from_bytes(self._data[name_end + 4:name_end + 8], 'big')
		data_length = int.from_bytes(
				self._data[name_end + 8:name_end + 10], 'big')
		data = self._data[name_end + 10: name_end + 10 + data_length]
		record = DNSResourceRecord(name, record_type, record_class, ttl, data)
		if record.type == Types['NS']:
			record.data, _ = self._read_name(name_end + 10)

		return record, name_end + data_length + 10

	def _read_name(self, start: int):
		parts = []
		end_name_position = pointer = start

		while self._data[pointer]:
			name_type = self._data[pointer] >> 6
			if not name_type:
				current = self._data[pointer]
				parts.append(
						self._data[pointer + 1:pointer + 1 + current])
				pointer = pointer + current + 1
			else:
				url = ((((self._data[pointer] << 2) & 0xFF) << 6)
						| self._data[pointer + 1])
				end_name_position = max(end_name_position, pointer + 1)
				pointer = url
			end_name_position = max(end_name_position, pointer)

		return b'.'.join(parts), end_name_position + 1
