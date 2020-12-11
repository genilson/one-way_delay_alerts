import argparse
import json
import socket
import sys
import time
import serial
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
client_server_group.add_argument('-r', '--interface', dest='serial_if', metavar='interface', type=str, default='/dev/ttyUSB0',
                                 help='If a timer/counter is to be used, this serial interface has access to it (default /dev/ttyUSB0)')

server_group = parser.add_argument_group('Server specific')
# Timeout 
server_group.add_argument('-t', '--time-out', type=float, dest='timeout', metavar='#', default=5.0, help='Timeout in seconds after last packet received (default 5s)')
# Log names
server_group.add_argument('-l', '--log-prefix', dest='log_prefix', type=str, default='', metavar='log prefix',
                          help='Prefix for log file. Base name is xyz_dd_mm_yy_hh_mm_ss_delays.csv, where xyz is the last octet of client\'s IP address')

client_group = parser.add_argument_group('Client specific')
client_group.add_argument('-n', '--num-packets', type=int, dest='num_pkts', metavar='#', default=50, help='number of packets to send (default 50)')
# Inter-packet gap in seconds. Default is 10 milliseconds
client_group.add_argument('-i', '--inter', type=float, dest='inter_pkts', metavar='#', default=0.01, help='Inter-packet gap in seconds (default 0,01s)')

args = parser.parse_args();

# Connection to the arduino
data = serial.Serial(args.serial_if, 115200)

# Wait for serial connection to be established
time.sleep(2)

#Server mode
if args.server:  

    HOST = ''
    PORT = args.port

    # Global variables
    # Time that last packet was received
    last_pkt_time = 0.0

    # Dictionary with timer values for each package that was received
    timer_dict = {}

    def time_last_packet(pkt):
        global last_pkt_time
        last_pkt_time = pkt.time

        # Requesting timer from the arduino 
        data.write(b'r')
        counter = data.readline().strip()
        
        # Storing timer/counter value for each package
        timer_dict[pkt.id] = counter.decode('utf-8')

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    orig = (HOST, PORT)

    tcp.bind(orig)
    tcp.listen(1)

    try:
        # Running the server
        while True:

            # Getting parameters from client
            con,client = tcp.accept()
            num_pkts_client = int.from_bytes(con.recv(100),'little')
            con.close()

            last_pkt_time = 0.0

            # Setting asynchronous sniffer
            result = AsyncSniffer(prn=time_last_packet,filter='udp port {}'.format(args.alert_port), count=num_pkts_client)
            result.start()

            print('Sniffing {} packets from {} on port {}'.format(num_pkts_client, client[0], args.alert_port))

            # The loop only leaves when num_pkts packets were received, or
            # timeout after last received packet is reached                                                       
            while result.running: 
                if last_pkt_time != 0.0:
                    if (time.time() - last_pkt_time) >= args.timeout:
                        result.stop()
                        print('Sniffer stopped after timeout')
                        print(result.results)

            # Giving the sniffer time to stop
            time.sleep(2)

            # Dictionary with info about sniffed packets
            sniffed_dict = {int(pkt.id): (float(pkt.time),int(timer_dict[pkt.id])) for pkt in result.results}

            print('Pacotes capturados: ')
            print(sniffed_dict)

            # Getting info from the client about packets that were sent
            con, client = tcp.accept()
            print('Connection from {} established'.format(client))
            print('Getting information on sent packages from client')
            chunks = []
            while True:
                msg = con.recv(1024)
                if not msg:
                    break
                else:
                    chunks.append(msg)
            print('Closing connection with {}'.format(client))
            con.close()

            # Decoding the message into a dictionary
            recv_dict = {int(pkt_id): (float(pkt_sent_time),int(pkt_sent_counter)) for (pkt_id,(pkt_sent_time,pkt_sent_counter)) in json.loads(
                b''.join(chunks).decode()).items()}
            print('Pacotes enviados: ')
            print(recv_dict)
            
            # Lost packets get a nan value for delay. Total loss is logged
            loss = 0
            log = open(args.log_prefix+client[0].split('.')[-1]+'_'+time.strftime('%d_%m_%Y_%H_%M_%S')+'_delays.csv', 'w')
            log.write('id,delay\n')

            print('Calculating and logging packets delays and packet loss')

            # Recv_dict has info about app packets that were sent, regardless if they
            # were received or not
            for pkt_id in recv_dict.keys():
                if pkt_id in sniffed_dict.keys():
                    delay = (sniffed_dict[pkt_id][1] - recv_dict[pkt_id][1])
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
    HOST = args.host
    PORT = args.port
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest = (HOST, PORT)

    # Dictionary with timer values for each package that was sent
    timer_dict = {}

    # Sending parameters info
    tcp.connect(dest)
    tcp.sendall((args.num_pkts).to_bytes(((args.num_pkts).bit_length() + 7) // 8, 'little'))
    #tcp.close()

    # Giving the sniffer time to start
    time.sleep(2)

    # Sending packets and storing their ids, timestamps and timer/counter value
    pkts_sent = []

    for i in range(1,args.num_pkts+1):
        pkt = IP(dst=args.host, id=i,tos=192)/UDP(dport=args.alert_port)
        pkts_sent.append(send(pkt, inter=args.inter_pkts, return_packets=True))
        # Requesting timer from the arduino 
        data.write(b'r')
        counter = data.readline().strip()
        # Storing timer/counter value for each package
        timer_dict[i] = counter.decode('utf-8')
    
    # Creating a dict with id as key for timestamp of sent packets
    infos = {p[0].id:(p[0].sent_time,timer_dict[p[0].id]) for p in pkts_sent}
    print('Informações enviadas ao servidor: ')
    print(infos)

    # Sending infos to the server
    encoded_msg = json.dumps(infos).encode('utf-8')

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect(dest)
    tcp.sendall(encoded_msg)
    tcp.close()
    data.close()
    
# if args.server and 'num_pkts' in vars(args):
#     parser.error("number of packages is a client side option")

#Server
    

#Client