import argparse
from scapy.all import *

parser = argparse.ArgumentParser(description="Sends/receives medical alerts\
                                              from WBAN and calculates package\
                                              delay and package loss",
                                              usage='alerts [-s|-c host] [options]')

group = parser.add_mutually_exclusive_group()
group.add_argument('-s', '--server', help='run in server mode',
                    action='store_true')
group.add_argument('-c', '--client', dest='host', metavar='host', help='run in client mode, connecting to\
                   <host>')

client_server_group = parser.add_argument_group('Client/Server')
client_server_group.add_argument('-p','--port', dest='port', metavar='#', type=int, default=6000, help='server port to listen on/connect to')

server_group = parser.add_argument_group('Server specific')

client_group = parser.add_argument_group('Client specific')
client_group.add_argument('-n', '--num-packets', type=int, dest='num_pkts', metavar='#', default=50, help='number of packets to send')

args = parser.parse_args();

#Server
print("Host: {}, Porta: {}, Número de pacotes: {}".format(args.host,  args.port,  args.num_pkts))

#Client