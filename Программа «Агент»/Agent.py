from scapy.all import *
import time
import csv
import socket
import os


def send_stat():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = 29541
    s.connect((IP_server, port))

    with open('data.csv', 'rb') as f:
        data = f.read(1024)
        while data:
            s.send(data)
            data = f.read(1024)

    s.close()
    os.remove("data.csv")
def update_statistics(packet):
    if IP or ICMP in packet:

        protocol_name = packet.getlayer(2).name
        protocols_count[protocol_name] = protocols_count.get(protocol_name, 0) + 1

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        connection_duration = packet.time
        if protocol_name in protocols_duration:
            if src_ip in protocols_duration[protocol_name]:
                protocols_duration[protocol_name][src_ip] += connection_duration
            else:
                protocols_duration[protocol_name][src_ip] = connection_duration
            if dst_ip in protocols_duration[protocol_name]:
                protocols_duration[protocol_name][dst_ip] += connection_duration
            else:
                protocols_duration[protocol_name][dst_ip] = connection_duration
        else:
            protocols_duration[protocol_name] = {src_ip: connection_duration, dst_ip: connection_duration}

        traffic_size = len(packet)
        protocols_traffic[protocol_name] = protocols_traffic.get(protocol_name, 0) + traffic_size

        current_time = time.time()
        if 'last_packet_time' in update_statistics.__dict__:
            time_diff = current_time - update_statistics.last_packet_time
            for prot in protocols_count:
                protocols_speed[prot] = protocols_traffic[prot] / (time_diff+0.001)
        update_statistics.last_packet_time = current_time

def packet_callback(packet):
    if IP in packet:
        info = []
        with open('data.csv', 'w', newline="") as file:
            writer = csv.writer(file)
            update_statistics(packet)
            info.append(packet.getlayer(0).name)

            Proto_2 = packet[Ether].type
            if Proto_2 == 0x0800:
                Proto_2 = "IPv4"
            elif Proto_2 == 0x86DD:
                Proto_2 = "IPv6"
            elif Proto_2 == 0x8100:
                Proto_2 = "IPv4"
            else: Proto_2 = "Неизвестный_протокол"
            info.append(Proto_2)

            info.append(packet.getlayer(1).name) 
            if TCP in packet:
                info.append("TCP")
            elif UDP in packet:
                info.append("UDP")
            elif ICMP in packet:
                info.append("ICMP")
            elif "ftp" in packet:
                info.append("FTP")
            else: info.append("None")
            


            info.append(packet[IP].src)
            info.append(packet[IP].dst) 

            if packet.haslayer(TCP): 
                tcp_flags = packet.getlayer(TCP).flags  
                if tcp_flags & 0x02:
                    info.append(1)  
                else:
                    info.append(0)
                if tcp_flags & 0x10:
                    info.append(1)  
                else:
                    info.append(0)
                if tcp_flags & 0x08:
                    info.append(1)  
                else:
                    info.append(0)
                if tcp_flags & 0x04:
                    info.append(1)  
                else:
                    info.append(0)
                if tcp_flags & 0x20:
                    info.append(1)  
                else:
                    info.append(0)
                if tcp_flags & 0x01:
                    info.append(1)  
                else:
                    info.append(0)
            else:
                for i in range(6): info.append(0)

            if packet.haslayer(Raw):  
                data_size = len(packet.getlayer(Raw).load)
                info.append(data_size)
            else: info.append(10)

            if IP in packet:  
                if packet.haslayer(TCP):
                    info.append(packet[TCP].sport)
                    info.append(packet[TCP].dport)
                elif packet.haslayer(UDP):
                    info.append(packet[UDP].sport)
                    info.append(packet[UDP].dport)

            else:
                info.append(0)
                info.append(0)

            if ICMP in packet:  
                icmp_length = len(packet[ICMP].payload)
                info.append(icmp_length)
            else:info.append(0)

            if packet.haslayer(TCP): 
                window_size = packet.getlayer(TCP).window 
                info.append(window_size)
            else:info.append(0)

            ttl_value = packet.ttl  
            info.append(ttl_value)
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            info.append(src_mac) 
            info.append(dst_mac) 
            summary.append(info)
            writer.writerows([tuple(info)])

def end_stat(summary):

    proto_durations = [value for inner_dict in protocols_duration.values() for value in inner_dict.values()]
    proto_count = [value for value in protocols_count.values()]
    proto_traffic = [value for value in protocols_traffic.values()]
    proto_speed = [value for value in protocols_speed.values()]

    for i in range(len(summary)):

        if summary[i][3] == "TCP":
            proto_dur_TCP = [value for value in protocols_duration.get('TCP', {}).values() if
                              isinstance(value, (int, float))]
            summary[i].append(round(sum(proto_durations)))  
            summary[i].append(sum(proto_count))             
            summary[i].append(protocols_count.get("TCP"))   
            summary[i].append(round(sum(proto_dur_TCP)))    
            summary[i].append(sum(proto_traffic))           
            summary[i].append(protocols_traffic.get("TCP")) 
            summary[i].append(round(sum(proto_speed)))      
            summary[i].append(round(protocols_speed.get("TCP")))   

        elif summary[i][3] == "UDP":
            proto_dur_UDP = [value for value in protocols_duration.get('UDP', {}).values() if
                              isinstance(value, (int, float))]
            summary[i].append(round(sum(proto_durations)))  
            summary[i].append(sum(proto_count))             
            summary[i].append(protocols_count.get("UDP"))   
            summary[i].append(round(sum(proto_dur_UDP)))    
            summary[i].append(sum(proto_traffic))           
            summary[i].append(protocols_traffic.get("UDP")) 
            summary[i].append(round(sum(proto_speed)))      
            summary[i].append(round(protocols_speed.get("UDP")))   

        elif summary[i][3] == "FTP":
            proto_dur_FTP = [value for value in protocols_duration.get('FTP', {}).values() if
                              isinstance(value, (int, float))]
            summary[i].append(round(sum(proto_durations)))  
            summary[i].append(sum(proto_count))             
            summary[i].append(protocols_count.get("FTP"))   
            summary[i].append(round(sum(proto_dur_FTP)))    
            summary[i].append(sum(proto_traffic))           
            summary[i].append(protocols_traffic.get("FTP")) 
            summary[i].append(round(sum(proto_speed)))      
            summary[i].append(round(protocols_speed.get("FTP")))   
        else:
            for e in range(6):
                summary[i].append(0)
        if summary[i][3] == "ICMP":
            proto_dur_ICMP = [value for value in protocols_duration.get('ICMP', {}).values() if
                              isinstance(value, (int, float))]
            summary[i].append(round(sum(proto_durations)))         
            summary[i].append(sum(proto_count))                     
            summary[i].append(protocols_count.get("ICMP"))          
            summary[i].append(round(sum(proto_dur_ICMP)))           
            summary[i].append(sum(proto_traffic))                   
            summary[i].append(protocols_traffic.get("ICMP"))        
            summary[i].append(round(sum(proto_speed)))             
            summary[i].append(round(protocols_speed.get("ICMP")))   

    return summary

def save_log(summary):
    with open('data.csv', 'w', newline="") as file:
        for i in range(len(summary)):
            if len(summary[i]) < 28:
                for e in range(len(summary[i]),28 - 2):
                    summary[i].append(0)
            writer = csv.writer(file)
            writer.writerows([tuple(summary[i])])

        summary = []
        return summary


protocols_count = {}
protocols_duration = {}
protocols_traffic = {}
protocols_speed = {}
summary = []
IP_server = input("Введите адрес сервера - ")
T = int(input("Введите время между отправкой - "))

while True:

    sniff(prn=packet_callback, timeout = T) 
    end_stat(summary)
    save_log(summary)
    send_stat()
    summary = []

