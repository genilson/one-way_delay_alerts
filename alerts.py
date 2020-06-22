import argparse
import json
import socket
import _thread
import time
from scapy.all import *

parser = argparse.ArgumentParser(description='Sends/receives medical alerts from WBAN and calculates package delay and package loss',
                                              usage='alerts [-s|-c host] [options]',
                                              epilog='Source at:\n\
                                                     report bugs to: <genilsonisrael@gmail.com>')

group = parser.add_mutually_exclusive_group()
group.add_argument('-s', '--server', dest='server', help='run in server mode', action='store_true')
group.add_argument('-c', '--client', dest='host', metavar='host', help='run in client mode, connecting to\
                   <host>')

client_server_group = parser.add_argument_group('Client/Server')
client_server_group.add_argument('-p','--port', dest='port', metavar='#', type=int, default=6000, help='server port to listen on/connect to')

server_group = parser.add_argument_group('Server specific')

client_group = parser.add_argument_group('Client specific')
client_group.add_argument('-n', '--num-packets', type=int, dest='num_pkts', metavar='#', default=50, help='number of packets to send')

# SUBCOMANDOS
# subparsers = parser.add_subparsers(help='Client or Server mode')

# server_parser = subparsers.add_parser('server', help='run in server mode')
# server_parser.add_argument('-t', help='timeout')
# server_parser.add_argument('-p','--port', dest='port', metavar='#', type=int, default=6000, help='server port to listen on')

# client_parser = subparsers.add_parser('client', help='run in client mode')
# client_parser.add_argument('-n', help='number of packets')
# client_parser.add_argument('-p','--port', dest='port', metavar='#', type=int, default=6000, help='server port to connect to')

args = parser.parse_args();

#Server mode
if args.server:  

    # Put it inside the thread
    #sniffed = sniff(filter='port 50000')


    HOST = ''
    PORT = args.port

    def connection(con, client):
        print('Connection from {} established'.format(client))
        chunks = []
        while True:
            msg = con.recv(1024)
            if not msg:
                break
            else:
                chunks.append(msg)
        decoded_msg = json.loads(b''.join(chunks).decode())
        print(decoded_msg)
        print('Closing connection with {}'.format(client))
        con.close()
        _thread.exit()

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    orig = (HOST, PORT)

    tcp.bind(orig)
    tcp.listen(1)

    # Running the server
    while True:
        con, client = tcp.accept()
        _thread.start_new_thread(connection, tuple([con, client]))

    # Not supposed to be here
    # for p in sniffed:
    #     print(p.time)

    tcp.close()

# Client mode
else:
    print('Teste')
    # Sending packets and storing their ids and sent timestamps
    # TODO: Set correct TOS and DSCP fields
    pkts_sent = send(IP(dst=args.host, id=RandShort())/UDP(), count=args.num_pkts, return_packets=True)
    
    # Creating a dict with id as key for timestamp of sent packets
    infos = {p.id:p.sent_time for p in pkts_sent}

    # Sending infos to the server
    HOST = args.host
    PORT = args.port
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest = (HOST, PORT)
    tcp.connect(dest)
    
    encoded_msg = json.dumps(infos).encode('utf-8')
    tcp.sendall(encoded_msg)
    tcp.close()
    
# if args.server and 'num_pkts' in vars(args):
#     parser.error("number of packages is a client side option")

#Server
    

#Client