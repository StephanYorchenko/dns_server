import asyncio
import socket
from collections import namedtuple
from random import randint

from dns import DNSCreator, DNSPacket, DNSHeaderFlags, DNSResourceRecord, \
	DNSQuestion, Types

PORT = 8686
HOST = '0.0.0.0'
SERVER = (HOST, PORT)
START_SERVER = ('198.41.0.4', 53)

send_pair = namedtuple('send_pair', 'pack addr')


class DNSServer:
	def __init__(self):
		self.loop = None
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.bind(SERVER)

	@staticmethod
	async def send_request(req_ip, req_domain, sock):
		print(req_ip)
		questions = [DNSQuestion(req_domain.encode())]
		to_send = DNSCreator(questions,
							 flags=DNSHeaderFlags.generate_flags().to_bytes(),
							 id=randint(0, 0xFFFF))
		sock.sendto(to_send.create(), req_ip)
		data, addr = sock.recvfrom(16384)
		return DNSPacket(data)

	async def resolve_ip(self, addr, domain, sock):
		response = await self.send_request(addr, domain, sock)
		additional_with_ip = list(
				filter(lambda x: x.type == Types['A'], response.additional))

		if len(response.answers):
			return ['.'.join(map(str, ans.data)) for ans in response.answers]

		if additional_with_ip:
			ip = '.'.join(map(str, additional_with_ip[0].data))
			return await self.resolve_ip((ip, 53), domain, sock)
		else:
			ns_authorities = list(
				filter(lambda x: x.type == Types['NS'], response.authority))

			if ns_authorities:
				ns = ns_authorities[0].data.decode()
				ips = await self.resolve_ip(START_SERVER, ns, sock)
				authority_ip = ips[0] if ips is not None else None
				return await self.resolve_ip((authority_ip, 53), domain, sock)

	async def handle_client(self, conn, addr):
		client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		packet = DNSPacket(conn)
		req_id = packet.header.id

		if not len(packet.queries):
			self.sock.sendto(DNSCreator(id=req_id).create(), addr)
			return
		domain = packet.queries[0].qname

		ips = await self.resolve_ip(START_SERVER, domain.decode(), client_sock) or []
		answer_request = DNSCreator(id=req_id)
		for ip in ips:
			answer_request.add_answer(
					DNSResourceRecord(domain, data=b''.join(
							int(x).to_bytes(1, 'big') for x in ip.split('.')))
			)

		answer_request.flags = DNSHeaderFlags.generate_flags(qa=1).to_bytes()
		self.sock.sendto(answer_request.create(), addr)
		client_sock.close()

	async def listen(self):
		while True:
			conn, addr = self.sock.recvfrom(16384)
			await self.handle_client(conn, addr)

	def run(self):
		self.loop = asyncio.get_event_loop()
		self.loop.run_until_complete(self.listen())

	def __exit__(self, exc_type, exc_val, exc_tb):
		self.sock.close()


if __name__ == '__main__':
	server = DNSServer()
	server.run()
