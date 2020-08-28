import argparse
import json
import socket
import sys
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
client_server_group.add_argument('-p','--port', dest='port', metavar='#', type=int, default=5000, help='server port to listen on/connect to (default 5000)')
client_server_group.add_argument('-a', '--alert-port', dest='alert_port', metavar='#', type=int, default=6000,
                                 help='port in which to send/sniff alert packets (default 6000)')

server_group = parser.add_argument_group('Server specific')
# Timeout 
server_group.add_argument('-t', '--time-out', type=float, dest='timeout', metavar='#', default=5.0, help='Timeout in seconds (default 5s)')

client_group = parser.add_argument_group('Client specific')
client_group.add_argument('-n', '--num-packets', type=int, dest='num_pkts', metavar='#', default=50, help='number of packets to send (default 50)')
# Inter-packet gap in seconds. Default is 10 milliseconds
client_group.add_argument('-i', '--inter', type=float, dest='inter_pkts', metavar='#', default=0.01, help='Interpacket gap (default 10ms)')

args = parser.parse_args();

#Server mode
if args.server:  

    HOST = ''
    PORT = args.port

    # Global variables
    # Time that last packet was received
    last_pkt_time = 0.0

    def time_last_packet(pkt):
        global last_pkt_time
        last_pkt_time = pkt.time

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    orig = (HOST, PORT)

    tcp.bind(orig)
    tcp.listen(1)

    try:
        # Running the server
        while True:
            last_pkt_time = 0.0

            # Setting asynchronous sniffer
            result = AsyncSniffer(prn=time_last_packet,filter='udp port {}'.format(args.alert_port), count=args.num_pkts)

            result.start()

            print('Sniffing packets on port {}'.format(args.alert_port))

            # The loop only leaves when num_pkts packets were received, or
            # timeout after last received packet is reached                                                       
            while result.running: 
                if last_pkt_time != 0.0:
                    if (time.time() - last_pkt_time) >= args.timeout:
                        result.stop()

            # Giving the sniffer the time it needs to stop
            time.sleep(0.5)

            # Dictionary with info about sniffed packets           
            sniffed_dict = {pkt.id: pkt.time for pkt in result.results}

            # Getting info from the client about packets that were sent
            con, client = tcp.accept()
            print('Connection from {} established'.format(client))
            chunks = []
            while True:
                msg = con.recv(1024)
                if not msg:
                    break
                else:
                    chunks.append(msg)
            print('Closing connection with {}'.format(client))
            #print('Got {} bytes from {}'.format(sys.getsizeof(chunks),client))
            con.close()

            # Decoding the message into a dictionary
            recv_dict = {int(pkt_id): float(pkt_sent_time) for (pkt_id,pkt_sent_time) in json.loads(
                b''.join(chunks).decode()).items()}
            
            # Lost packets get a nan value for delay. Total loss is logged
            loss = 0
            log = open(time.strftime('%d_%m_%Y_%H_%M_%S')+'_delays.csv', 'w')
            log.write('id,delay\n')

            # Recv_dict has info about app packets that were sent, regardless if they
            # were received or not
            for pkt_id in recv_dict.keys():
                if pkt_id in sniffed_dict.keys():
                    delay = (sniffed_dict[pkt_id] - recv_dict[pkt_id]) * 1000
                else:
                    delay = 'nan'
                    loss += 1
                log.write(str(pkt_id) + ',' + str(delay) + '\n')
                print('Packet id: {} - Delay: {}'.format(pkt_id,delay))
            log.write('loss, {}'.format(loss))
            log.close()
            print('Packet loss: {}'.format(loss))
    except KeyboardInterrupt:
        print('Interrupting the server')
    tcp.close()

# Client mode
else:
    # Sending packets and storing their ids and sent timestamps
    # TODO: Set correct TOS and DSCP fields
    pkts_sent = send(IP(dst=args.host, id=range(1,args.num_pkts+1),tos=192)/UDP(dport=args.alert_port),
                                                inter=args.inter_pkts, return_packets=True)
    
    # Creating a dict with id as key for timestamp of sent packets
    infos = {p.id:p.sent_time for p in pkts_sent}

    # Sending infos to the server
    encoded_msg = json.dumps(infos).encode('utf-8')

    HOST = args.host
    PORT = args.port
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest = (HOST, PORT)
    tcp.connect(dest)
    tcp.sendall(encoded_msg)
    #print('Sent {} bytes to {}'.format(sys.getsizeof(bytes(encoded_msg)), args.host))
    tcp.close()
    
# if args.server and 'num_pkts' in vars(args):
#     parser.error("number of packages is a client side option")

#Server
    

#Client