from .dns_base import Types
from .dns_header import DNSHeader
from .dns_question import DNSQuestion
from .dns_record import DNSResourceRecord


class DNSPacket:
	def __init__(self, data: bytes):
		self._data = data
		pointer = 12
		self.header = DNSHeader(data[:pointer])

		self.queries, pointer = self._read_n_records(
				self._parse_query,
				self.header.qd_count,
				pointer)
		self.answers, pointer = self._read_n_records(
				self._parse_resource_record,
				self.header.ans_count,
				pointer)
		self.authority, pointer = self._read_n_records(
				self._parse_resource_record,
				self.header.ns_count,
				pointer)
		self.additional, pointer = self._read_n_records(
				self._parse_resource_record,
				self.header.ar_count,
				pointer)

	@staticmethod
	def _read_n_records(parse_func, count, start):
		index, result = start, []
		for i in range(count):
			parsed_obj, ind = parse_func(index)
			result.append(parsed_obj)
			index = ind

		return result, index

	def _parse_query(self, start):
		name, name_end = self._parse_name_and_find_end(start)
		q_type = int.from_bytes(self._data[name_end:name_end + 2], 'big')
		q_class = int.from_bytes(self._data[name_end + 2:name_end + 4], 'big')
		return DNSQuestion(name, q_type, q_class), name_end + 4

	def _parse_resource_record(self, start):
		name, name_end = self._parse_name_and_find_end(start)
		r_type = int.from_bytes(self._data[name_end:name_end + 2], 'big')
		r_class = int.from_bytes(self._data[name_end + 2:name_end + 4], 'big')
		ttl = int.from_bytes(self._data[name_end + 4:name_end + 8], 'big')
		data_length = int.from_bytes(
				self._data[name_end + 8:name_end + 10],
				'big')
		data = self._data[name_end + 10: name_end + 10 + data_length]

		record = DNSResourceRecord(name, r_type, r_class, ttl, data)
		if record.type == Types['NS']:
			record.data, _ = self._parse_name_and_find_end(name_end + 10)

		return record, name_end + data_length + 10

	def _parse_name_and_find_end(self, start: int):
		parts = []
		name_end = start
		last_end = start

		while True:
			if not self._data[last_end]:
				break

			name_type = self._data[last_end] >> 6
			if name_type == 0b00:
				cur_length = self._data[last_end]
				parts.append(
						self._data[last_end + 1:last_end + 1 + cur_length])
				last_end = last_end + cur_length + 1
			else:
				link = ((((self._data[last_end] << 2) & 0xFF) << 6)
						| self._data[last_end + 1])
				name_end = max(name_end, last_end + 1)
				last_end = link

			name_end = max(name_end, last_end)

		return b'.'.join(parts), name_end + 1
