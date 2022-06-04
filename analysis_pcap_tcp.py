from turtle import window_width
import dpkt as dp
import sys
import socket
from prettytable import PrettyTable

# globals
TH_FIN = 0x01 # end of data
TH_SYN = 0x02
TH_RST = 0x04
TH_PUSH = 0x08
TH_ACK = 0x10
TH_URG = 0x20
TH_ECE = 0x40
TH_CWR = 0x80
TH_NS = 0x100

# classes

class Packet():
    def __init__(self, pcap, timestamp):
        self.ethernet = dp.ethernet.Ethernet(pcap)
        self.ip_address = self.ethernet.data
        self.tcp = self.ip_address.data
        self.sport = self.tcp.sport
        self.dport = self.tcp.dport
        self.src_ip = get_ip_addr_string(self.ip_address.src)
        self.dst_ip = get_ip_addr_string(self.ip_address.dst)
        self.timestamp = timestamp # don't need to put into seconds

    def get_id(self):
        return (self.sport, self.src_ip, self.dport, self.dst_ip)

    def get_tcp_size(self):
        return len(self.tcp)

    def get_size_of_payload(self):
        return len(self.tcp.data)
    
    def get_tcp_flags(self):
        return self.tcp.flags

    def get_src_ip(self):
        return self.src_ip

    def get_dst_ip(self):
        return self.dst_ip

    def get_sequence_num(self):
        return self.tcp.seq

    def get_ack_num(self):
        return self.tcp.ack

    def get_window_size(self):
        return self.tcp.win

    def get_timestamp(self):
        return self.timestamp

class TCPFlow():
    def __init__(self, sender, receiver):
        self.sender = sender
        self.receiver = receiver
        # sorts packets by sender
        self.flow = sorted(self.sender + self.receiver, key=lambda x: x[0])
        # removes the syn, syn ack, etc and places them in the handshake
        self.__ignore_handshake()

        opts = dp.tcp.parse_opts(self.handshake[0][2].tcp.opts)
        vals = []
        for opt, value in opts:
            if opt == dp.tcp.TCP_OPT_WSCALE:
                vals.append(value)
        window_scale = vals[0] # this is a hex value
        self.win_scaling = 2 ** int(window_scale.hex(), base=16)
        # self.timestamp = timestamp

    def __ignore_handshake(self):
        # need the first SYN packet
        syn = None
        for pk in self.sender:
            if pk[2].get_tcp_flags() & TH_SYN:
                syn = pk
                break
        if syn == None: print("No SYN found from Sender.")
        # now that we have the SYN, we need to get the SYN ACK from the recv
        # this ack will be = seq of send + 1 
        syn_ack = None
        for pk in self.receiver:
            current_ack = pk[2].get_ack_num()
            prev_seq = syn[2].get_sequence_num()
            if pk[2].get_tcp_flags() & TH_SYN and pk[2].get_tcp_flags() & TH_ACK and (current_ack == (prev_seq + 1)):
                syn_ack = pk
                break
        if syn_ack == None: print("No SYN found from Receiver.")

        # now we need the single ack
        # this ack will be = syn ack seq + 1
        ack = None
        for pk in self.sender:
            if pk[2].get_tcp_flags() == TH_ACK:
                current_ack = pk[2].get_ack_num()
                prev_seq = syn_ack[2].get_sequence_num()
                if current_ack == (prev_seq + 1):
                    ack = pk
                    break
        if ack == None: print("No ACK from Sender.")

        index = self.flow.index(ack)
        self.handshake = self.flow[:index + 1]
        # check if a piggy back exists
        if ack[2].get_size_of_payload() != 0:
            index = index - 1
            
        self.flow = self.flow[index + 1:]

    def get_transactions(self):
        """
            Gets the first two transactions as a default and returns as a list.
        """
        packet1 = []
        count = 0
        # finding the request
        for (c, ts, packet) in self.flow:
            if packet.get_src_ip() == "130.245.145.12": # sender
                count += 1
                pk = (packet.get_src_ip(), packet.get_dst_ip(), packet.get_sequence_num(), packet.get_ack_num(), packet.get_window_size(), packet.get_timestamp())
                packet1.append(pk)
            if count == 2:
                break
        
        count = 0
        packet2 = []
        # need to find the response
        for (c, ts, packet) in self.flow:
            if packet.get_src_ip() == "128.208.2.198": # receiver
                count += 1
                pk = (packet.get_src_ip(), packet.get_dst_ip(), packet.get_sequence_num(), packet.get_ack_num(), packet.get_window_size(), packet.get_timestamp())
                packet2.append(pk)
            if count == 2:
                break

        packets = [packet1[0], packet2[0], packet1[1], packet2[1]]
        return packets

    def get_id(self):
        return self.sender[0][-1].get_id()

    #calculate the sender throuput for each flow
    def sender_throughput(self):
        """
        Estimates the sender throughput for each flow and returns as a pair of data bytes summed and the time period.
        """
        count = data = 0
        fin_ack = None
        for pk in self.receiver:
            if pk[2].get_tcp_flags() & TH_FIN and pk[2].get_tcp_flags() & TH_ACK: # check if it is fin ack
                fin_ack = pk
        
        # get index of last fin_ack packet in flow
        # we want to skip and not include this packet
        # the "handshake" packets are already not included from a 
        # previous method
        index = self.flow.index(fin_ack)
        flow = self.flow[:index + 1]
        time_period = flow[-1][1] - flow[0][1]
        for pk in flow:
            if pk[2].get_src_ip() == "130.245.145.12": # sender
                count += 1
                data += pk[2].get_tcp_size()
        # print(count)

        return data, time_period

    # PART B
    # DONE
    def estimate_congestion_win_size(self):
        """
        Estimates 3 congestion window sizes and returns a list. 
        """
        # starting from the very first ACK that isn't a part of the
        # three way handshake
        # no need to worry about that since we already got rid of that
        # using __ignore_handshake()
        first_ack = None
        for (c, ts, packet) in self.flow:
            if packet.get_src_ip() == "128.208.2.198": # receiver
                first_ack = packet
                break
        start_time = self.flow[0][1] # flow time of first packet
        ts = first_ack.get_timestamp()
        # first we find SYN/ACK timestamp, 
        # then need to keep adding the number of packets 
        # until the time that has passed has exceeded the 1 RTT
        # caclulate the RTT
        RTT = ts - start_time
        RTT = round(RTT, ndigits=8)
        print("RTT: ", RTT)
        # get timestamps 
        # adding all the packets
        timestamps = []
        for (c, ts, packet) in self.flow:
            if packet.get_src_ip() == "130.245.145.12": # sender
                timestamps.append(ts)
        # subtract start time from each timestamp
        times = []
        for ts in timestamps:
            time = ts - start_time
            times.append(time)

        # find the breakpoints between RTT intervals
        breakpoints = []
        for index in range(1, 4): # because of 3 + 1
            bp = index * RTT
            breakpoints.append(bp)

        # get estimated window sizes
        window_sizes = []
        ts_count = 0
        for bp in breakpoints:
            bp_count = 0
            while ts_count < len(times):
                if bp < times[ts_count]:
                    window_sizes.append(bp_count)
                    break
                bp_count += 1
                ts_count += 1

        return window_sizes

    def find_tda_and_timeout_retransmissions(self):
        """
        Finds the packets that were either retransmitted due to triple duplicate ACKS or because of a tiemout. Returns a pair. 
        """
        # find triple dup acks receive (using ack num)
        received = dict()
        for pk in self.flow:
            if pk[2].get_src_ip() == "128.208.2.198": # receiver
                if pk[2].get_ack_num() not in received.keys():
                    ack = pk[2].get_ack_num()
                    received[ack] = 1
                else:
                    ack = pk[2].get_ack_num()
                    received[ack] += 1

        triple_duplicate_acks = []
        for key in received.keys():
            if received[key] > 3:
                triple_duplicate_acks.append(key)

        # print("triple: ", len(triple_duplicate_acks))

        # find duplicate acks sent (using seq num)

        sent = dict()
        for pk in self.flow:
            if pk[2].get_src_ip() == "130.245.145.12": # sender
                if pk[2].get_sequence_num() not in sent.keys():
                    seq = pk[2].get_sequence_num()
                    sent[seq] = 1
                else:
                    seq = pk[2].get_sequence_num()
                    sent[seq] += 1

        duplicate_seqs = []
        for key in sent.keys():
            if sent[key] > 1:
                duplicate_seqs.append(key)

        # print("dup: ", len(duplicate_seqs))

        # if the duplicates weren't resent, ignore them
        intersection = []
        for seq in duplicate_seqs:
            if seq in triple_duplicate_acks:
                intersection.append(seq)

        out_of_order = 0
        for num in intersection:
            first_dup_ack_count = None
            count = 0
            for pk in self.receiver:
                if pk[2].get_ack_num() == num:
                    count += 1
                if count == 2:
                    first_dup_ack_count = pk[0]
                    break

            # if the retransmission is out of order
            count = 0
            for pk in self.sender:
                if pk[2].get_sequence_num() == num:
                    count += 1
                if count == 2:
                    if first_dup_ack_count > pk[0]:
                        out_of_order += 1
                    break

        triple_duplicates = len(intersection) - out_of_order
        timeouts = len(duplicate_seqs) - triple_duplicates

        return triple_duplicates, timeouts

def get_ip_addr_string(data): # grabbed from dpkt documentation
    """
    Returns the IP addresss encode as 4 bytes in as . dot separated string.
    """
    data = data.hex()
    return ".".join([str(int(data[i:i + 2], base=16)) for i in range(0, len(data), 2)])

def inet_to_str(inet): # grabbed from dpkt documentation
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def read_pcap(pcap):
    """
        Reads in a PCAP file and returns a list of the distinct flows found in the file.
    """
    send = "130.245.145.12" # sender ip address
    recv = "128.208.2.198" # receiver ip address
    # send = "10.1.217.189"
    # recv = "23.185.0.2"
    count = 0
    tcp_flows = {}
    final_tcp_flows = []
    ids = []
    for ts, buffer in pcap:
        count = count + 1
        eth = dp.ethernet.Ethernet(buffer)
        if eth.type != dp.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        if ip.p != dp.ip.IP_PROTO_TCP:
            continue
        tcp = ip.data
        # need to check if the sender ip = sa and reciever ip = rx
        # print(inet_to_str(ip.src))
        # print(send)
        if not (inet_to_str(ip.src) == send and inet_to_str(ip.dst) == recv) and not (inet_to_str(ip.dst) == send and inet_to_str(ip.src) == recv):
            continue
        # print("here")
        ip_src = inet_to_str(ip.src)
        ip_dst = inet_to_str(ip.dst)
        current = (tcp.sport, ip_src, tcp.dport, ip_dst)
        # print(current)
        if ip_src == send:
            packet = current
        else:
            (tcp.dport, ip_dst, tcp.sport, ip_src)
        if packet not in ids:
            ids.append(packet)
        
        if current not in tcp_flows:
            tcp_flows[current] = []
        flow = (count, ts, Packet(buffer, ts))
        tcp_flows[current].append(flow)

    for src_ip in ids:
        dst_ip = src_ip[2:] + src_ip[:2]
        flow = TCPFlow(tcp_flows[src_ip], tcp_flows[dst_ip])
        final_tcp_flows.append(flow)

    return final_tcp_flows

def print_results(flows):
    """
        Prints the results and analyses of a Flow as a pretty table. 
     """
    print("There are a total of ", len(flows), " TCP flows in this .pcap file.\n")
    count = 1
    for tcp_flow in flows:
        print(f"Flow {count} Statistics: ")
        t = PrettyTable(['Source IP', 'Dest. IP', 'Source Port', 'Dest. Port'])
        (sport, src, dport, dst) = tcp_flow.get_id()
        t.add_row([sport, src, dport, dst])
        print(t)
        transactions = tcp_flow.get_transactions()
        print("\nFIRST TWO TRANSACTIONS AFTER TCP CONNECTION:")
        # t = PrettyTable(['Source IP', 'Dest. IP', 'Seq. #', 'Ack #', 'Receive Window Size', 'Time'])
        # t.title = "TRANSACTION 1:"
        table = PrettyTable()
        i = 1
        for trans in transactions:
            if i == 1:
                table.title = "TRANSACTION #1"
                table.field_names = ['Source IP', 'Dest. IP', 'Seq. #', 'Ack #', 'Receive Window Size', 'Time']
                table.add_row([trans[0], trans[1], trans[2], trans[3], trans[4], trans[5]])
                i = i + 1
            elif i == 2:
                table.add_row([trans[0], trans[1], trans[2], trans[3], trans[4], trans[5]])
                print(table)
                i = i + 1
            elif i == 3:
                table = PrettyTable()
                table.title = "TRANSACTION #2"
                table.field_names = ['Source IP', 'Dest. IP', 'Seq. #', 'Ack #', 'Receive Window Size', 'Time']
                table.add_row([trans[0], trans[1], trans[2], trans[3], trans[4], trans[5]])
                i = i + 1
            else:
                table.add_row([trans[0], trans[1], trans[2], trans[3], trans[4], trans[5]])
                print(table)
                i = i + 1
        data, period = tcp_flow.sender_throughput()
        windows = tcp_flow.estimate_congestion_win_size()
        dup_ack_retransmission, timeout_retransmission = tcp_flow.find_tda_and_timeout_retransmissions()
        
        print("\nSENDER THROUGHPUT: ", (data / period), "bytes per second with", data, "bytes sent in", period, "seconds")
        print("FIRST 3 CONGESTION WINDOW SIZES: ", windows)
        print("NUMBER OF RETRANSMISSIONS DUE TO TRIPLE DUPLICATE ACK: ", dup_ack_retransmission)
        print("NUMBER OF RETRANSMISSIONS DUE TO TIMEOUT: ", timeout_retransmission)
        print("\n")
        count = count + 1

            

# main method
def main():
    file_name = sys.argv[1]
    try: 
        if ".pcap" in file_name:
            file = open(file_name, 'rb')
            pcap = dp.pcap.Reader(file)
            flows = read_pcap(pcap)          
            print_results(flows)
        else:
            print("File not valid. Please enter a valid .pcap file name.")
        return
    except FileNotFoundError:
        print("File not valid. Please enter a valid .pcap file name.")

if __name__ == '__main__':
    try:
        main()
    except IndexError:
        print("Please specify the pcap file. \n For example: python3 analysis_pcap_tcp.py assignment2.pcap")
