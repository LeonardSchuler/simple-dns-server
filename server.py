import socket

# Constants
DNS_PORT = 53
BUFFER_SIZE = 512

# This dictionary represents our DNS records database
# Here we're hardcoding a single domain "example.com" to resolve to "1.2.3.4"
DNS_RECORDS = {
    'example.com': '1.2.3.4'
}

"""
DNS query & response: Details: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
1.) Header: 6*16bits = 96bits = 12bytes
    1.) 16 bit identifier that the querying entity can choose and should be returned by the response
    2.) 16 bit flags
    3.) 16 bit unsigned int specifying the number of questions
    4.) 16 bit unsigned int specifying the number of answers
    5.) 16 bit unsigned int specifying the number of nameserver records
    6.) 16 bit unsigned int specifying the number of additional resource records
    Flags:
        1 bit: 0 query, 1 response
        4 bits: OPCODE 0000 query, 0001 inverse query, 0002 status
        1 bit: Authorative Answer? 1 = yes, 0 no
        1 bit: Truncation?
        1 bit: Recursion desired?
        1 bit: Recursion available?
        3 bit: Reserved always 000
        4 bit: response code: 0000 no error, 0001 Format error, 0002 server fail, 0003 non-existant domain
2.) 
    

"""
def byte2bin(bs: bytes, sep='') -> str:
    res = []
    for b in bs:
        res.append(bin(b)[2:].zfill(8))
    return sep.join(res)

def create_response(dns_query: bytes):
    # note: query[0] is the first byte and casted to int by python
    # note: b'\x00 ' == b'\x00\x20' == 32
    transaction_id = dns_query[:2]
    query_flags = dns_query[2:4]
    qfb = byte2bin(query_flags)
    print(f"Received transaction id: {int.from_bytes(transaction_id)}")
    print(f"Received flags in decimals:\t{query_flags[0]} {query_flags[1]}")
    print(f"Received flags in hex:\t\t{query_flags.hex(' ')}")
    print(f"Received flags in binary:\t{byte2bin(query_flags, sep=' ')}")
    print("Flags splitted by meaning:\t{} {} {} {} {} {} {} {}".format(qfb[0], qfb[1:5], qfb[5], qfb[6], qfb[7], qfb[8], qfb[9:12], qfb[12:]))
    print(f"\tQuery (0)/Response (1)?", qfb[0])
    print(f"\tDNS -> IP (0000) / IP -> DNS (0001):", qfb[1:5])
    print(f"\tAuthoritative answer?", qfb[5])
    print(f"\tTruncation?", qfb[6])
    print(f"\tRecursion desired?", qfb[7])
    print(f"\tRecursion available?", qfb[8])
    print(f"\tReserved (should be 000)", qfb[9:12]) # also called Z field
    print(f"\tresponse code (0000 no error, 0001 Format error, 0002 server fail, 0003 non-existant domain):", qfb[12:])
    #flags = b'\x81\x80'  # '1000000110000000' standard response, recursion desired and avaialable, no error

    # 0x8580 == bin(0x8580) == 1000010110000000 == also includes authorative answer flag
    flags = int.to_bytes(0x85_80, length=2) # == b'\x85\x80'
    num_questions = int.to_bytes(0x00_01, length=2) # 0000 0001
    num_answers = int.to_bytes(0x00_01, length=2)
    num_nameservers = int.to_bytes(0x00_00, length=2)
    num_add_res = int.to_bytes(0x00_00, length=2)
    question = dns_query[12:] # after the header follows only the question
    # the question is terminated by a length of 0x00

    domain_name = ''
    pointer = 0
    while True:
        length = question[pointer] # automatically converts to int
        if length == 0:
            break
        domain_name += question[pointer + 1:pointer + length + 1].decode() + '.'
        pointer += length + 1
    domain_name = domain_name[:-1]  # remove last '.'

    # Check if the domain name exists in our DNS_RECORDS
    if domain_name in DNS_RECORDS:
        # for message compression see: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
        # a pointer to an already defined domain should start with binary 11
        # the remaining 14 bits the define the offset to look for the domain
        # here that is after 12bytes (0c)
        # remember that the the header was 96bits = 12bytes long
        # and we will craft our final response by parroting back the question to the client
        answer = b'\xc0\x0c'  # pointer to domain name == byte2bin(b'\xc0\x0c',sep=' ') == '11000000 00001100' 
        answer += b'\x00\x01'  # Type: A
        answer += b'\x00\x01'  # Class: IN
        answer += b'\x00\x00\x00\x3c'  # TTL: 60 seconds = 3*16 + 12
        answer += b'\x00\x04'  # Data length: 4 bytes (IPv4)
        ip_parts = DNS_RECORDS[domain_name].split('.')
        answer += bytes([int(part) for part in ip_parts])
    else:
        flags = b'\x81\x83'  # No such name
        answer = b''

    return transaction_id + flags + num_questions + num_answers + num_nameservers + num_add_res + question + answer

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('127.0.0.1', DNS_PORT))
    print(f'DNS Server is running on port {DNS_PORT}')

    while True:
        query, addr = server_socket.recvfrom(BUFFER_SIZE)
        print(f"Query from {addr}.")
        response = create_response(query)
        server_socket.sendto(response, addr)

if __name__ == '__main__':
    main()
