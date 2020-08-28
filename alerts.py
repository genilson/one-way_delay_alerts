import argparse
import json
import queue
import socket
import _thread
import time
from threading import Thread
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

client_group = parser.add_argument_group('Client specific')
client_group.add_argument('-n', '--num-packets', type=int, dest='num_pkts', metavar='#', default=50, help='number of packets to send (default 50)')
# Inter-packet gap in seconds. Default is 10 milliseconds
client_group.add_argument('-i', '--inter', type=float, dest='inter_pkts', metavar='#', default=0.01, help='Interpacket gap (default 10ms)')

args = parser.parse_args();

#Server mode
if args.server:  

    HOST = ''
    PORT = args.port

    def capture_packets(port, num_packets, out_queue):
        sniffed = sniff(filter='udp port {}'.format(port), timeout=60, count=num_packets)
        time.sleep(1)
        sniffed_dict = {pkt.id: pkt.time for pkt in sniffed}
        out_queue.put(sniffed_dict)
        return
        # 
        #_thread.exit()
        #
        #Thread.exit() or just return?

    def connection(con, client, out_queue):
        print('Connection from {} established'.format(client))
        chunks = []
        while True:
            msg = con.recv(1024)
            if not msg:
                break
            else:
                chunks.append(msg)
        print('Closing connection with {}'.format(client))
        decoded_msg = {int(pkt_id): float(pkt_sent_time) for (pkt_id,pkt_sent_time) in json.loads(
            b''.join(chunks).decode()).items()}
        out_queue.put(decoded_msg)
        con.close()
        return
        #_thread.exit()
    
    cap_queue = queue.Queue()
    con_queue = queue.Queue()

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    orig = (HOST, PORT)

    tcp.bind(orig)
    tcp.listen(1)

    try:
        # Running the server
        while True:
            process = Thread(target=capture_packets, args=[args.alert_port, args.num_pkts, cap_queue])
            process.start()
            con, client = tcp.accept()
            process2 = Thread(target=connection, args=[con, client, con_queue])
            process2.start()

            # Waiting for the threads to finish
            while con_queue.empty() or cap_queue.empty():
                pass

            if not cap_queue.empty() and not con_queue.empty():
                cap = cap_queue.get()
                rec = con_queue.get()
                
                loss = 0
                log = open(time.strftime('%d_%m_%Y_%H_%M_%S')+'_delays.csv', 'w')
                log.write('id,delay\n')
                # Rec has info about app packets that were sent, regardless if they
                # were received or not
                for pkt_id in rec.keys():
                    if pkt_id in cap.keys():
                        delay = (cap[pkt_id] - rec[pkt_id]) * 1000
                    else:
                        delay = 'nan'
                        loss += 1
                    log.write(str(pkt_id) + ',' + str(delay) + '\n')
                    print('Packet id: {} - Delay: {}'.format(pkt_id,delay))
                log.close()
                print('Packet loss: {}'.format(loss))
    except KeyboardInterrupt:
        print('Interrupting the server')
        process.join()
        process2.join()
    tcp.close()

# Client mode
else:
    # Sending packets and storing their ids and sent timestamps
    # TODO: Set correct TOS and DSCP fields
    pkts_sent = send(IP(dst=args.host, id=range(1,args.num_pkts+1),tos=192)/UDP(dport=args.alert_port),
                                                inter=args.inter_pkts, return_packets=True)
    time.sleep(1)
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
    tcp.close()
    
# if args.server and 'num_pkts' in vars(args):
#     parser.error("number of packages is a client side option")

#Server
    

#Client