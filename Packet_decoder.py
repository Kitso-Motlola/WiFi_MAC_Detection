from scapy.all import *
from threading import Thread
from collections import Counter as cnt
import pandas
import time
import os

def enable_monitor_mode():
    os.system(f"sudo ip link set {interface} down")
    os.system(f"sudo iw {interface} set monitor none")
    os.system(f"sudo ip link set {interface} up")


def change_channel():
    channel = 1
    while end == 0:
        os.system(f"iwconfig {interface} channel {channel}")
        # switch channel from 1 to 14 each 0.5s
        channel = channel % 14 + 1
        time.sleep(0.25)

def packet_handler(packet):
    #str(packet[Dot11FCS].addr3)
    
    if packet.haslayer(Dot11FCS):
        # extract info from packet type control, block ack request:
        if packet[Dot11FCS].type == 1  and packet[Dot11FCS].subtype == 8: 
            packet_type = packet[Dot11FCS].type
            packet_subtype = packet[Dot11FCS].subtype
            destination_address = str(packet[Dot11FCS].addr1)
            sender_address = str(packet[Dot11FCS].addr2)
            BSSID = "null"
            Channel_freq = str(packet[RadioTap].ChannelFrequency)
            dBm_signal = str(packet[RadioTap].dBm_AntSignal)
            print("PKT_type: %s, PKT_subtype: %s, DA: %s, SA: %s, BSSID: %s, Freq: %s and dBm_signal: %s " %(packet_type, packet_subtype, destination_address, sender_address, BSSID, Channel_freq, dBm_signal))
        # extract info from packet type management, subtype action:    
        elif packet[Dot11FCS].type == 0  and packet[Dot11FCS].subtype == 13: 
            packet_type = packet[Dot11FCS].type
            packet_subtype = packet[Dot11FCS].subtype
            destination_address = str(packet[Dot11FCS].addr1)
            sender_address = str(packet[Dot11FCS].addr2)
            BSSID = "null"
            Channel_freq = str(packet[RadioTap].ChannelFrequency)
            dBm_signal = str(packet[RadioTap].dBm_AntSignal)
            print("PKT_type: %s, PKT_subtype: %s, DA: %s, SA: %s, BSSID: %s, Freq: %s and dBm_signal: %s " %(packet_type, packet_subtype, destination_address, sender_address, BSSID, Channel_freq, dBm_signal))
        # extract info from packet type management, subtype reassociation response:                 
        elif packet[Dot11FCS].type == 0  and packet[Dot11FCS].subtype == 3: 
            packet_type = packet[Dot11FCS].type
            packet_subtype = packet[Dot11FCS].subtype
            destination_address = str(packet[Dot11FCS].addr1)
            sender_address = str(packet[Dot11FCS].addr2)
            BSSID = str(packet[Dot11FCS].addr3)
            Channel_freq = str(packet[RadioTap].ChannelFrequency)
            dBm_signal = str(packet[RadioTap].dBm_AntSignal)
            print("PKT_type: %s, PKT_subtype: %s, DA: %s, SA: %s, BSSID: %s, Freq: %s and dBm_signal: %s " %(packet_type, packet_subtype, destination_address, sender_address, BSSID, Channel_freq, dBm_signal))
        # extract info from packet type extension, subtype 2:                 
        elif packet[Dot11FCS].type == 3  and packet[Dot11FCS].subtype == 2: 
            packet_type = packet[Dot11FCS].type
            packet_subtype = packet[Dot11FCS].subtype
            destination_address = str(packet[Dot11FCS].addr1)
            sender_address = "null"
            BSSID = str(packet[Dot11FCS].addr1)
            Channel_freq = str(packet[RadioTap].ChannelFrequency)
            dBm_signal = str(packet[RadioTap].dBm_AntSignal)
            print("PKT_type: %s, PKT_subtype: %s, DA: %s, SA: %s, BSSID: %s, Freq: %s and dBm_signal: %s " %(packet_type, packet_subtype, destination_address, sender_address, BSSID, Channel_freq, dBm_signal))
        # extract info from packet type data, subtype null:                 
        elif packet[Dot11FCS].type == 2  and packet[Dot11FCS].subtype == 4: 
            packet_type = packet[Dot11FCS].type
            packet_subtype = packet[Dot11FCS].subtype
            destination_address = str(packet[Dot11FCS].addr1)
            sender_address = str(packet[Dot11FCS].addr2)
            BSSID = str(packet[Dot11FCS].addr3)
            Channel_freq = str(packet[RadioTap].ChannelFrequency)
            dBm_signal = str(packet[RadioTap].dBm_AntSignal)
            print("PKT_type: %s, PKT_subtype: %s, DA: %s, SA: %s, BSSID: %s, Freq: %s and dBm_signal: %s " %(packet_type, packet_subtype, destination_address, sender_address, BSSID, Channel_freq, dBm_signal))
        # extract info from packet type management, subtype probe request:                 
        elif packet[Dot11FCS].type == 0  and packet[Dot11FCS].subtype == 4: 
            packet_type = packet[Dot11FCS].type
            packet_subtype = packet[Dot11FCS].subtype
            destination_address = str(packet[Dot11FCS].addr1)
            sender_address = str(packet[Dot11FCS].addr2)
            BSSID = str(packet[Dot11FCS].addr3)
            Channel_freq = str(packet[RadioTap].ChannelFrequency)
            dBm_signal = str(packet[RadioTap].dBm_AntSignal)
            print("PKT_type: %s, PKT_subtype: %s, DA: %s, SA: %s, BSSID: %s, Freq: %s and dBm_signal: %s " %(packet_type, packet_subtype, destination_address, sender_address, BSSID, Channel_freq, dBm_signal))
        # extract info from packet type management, subtype authentication:                 
        elif packet[Dot11FCS].type == 0  and packet[Dot11FCS].subtype == 11: 
            packet_type = packet[Dot11FCS].type
            packet_subtype = packet[Dot11FCS].subtype
            destination_address = str(packet[Dot11FCS].addr1)
            sender_address = str(packet[Dot11FCS].addr2)
            BSSID = str(packet[Dot11FCS].addr3)
            Channel_freq = str(packet[RadioTap].ChannelFrequency)
            dBm_signal = str(packet[RadioTap].dBm_AntSignal)
            print("PKT_type: %s, PKT_subtype: %s, DA: %s, SA: %s, BSSID: %s, Freq: %s and dBm_signal: %s " %(packet_type, packet_subtype, destination_address, sender_address, BSSID, Channel_freq, dBm_signal))
        # extract info from packet type management, subtype beacon:                 
        elif packet[Dot11FCS].type == 0  and packet[Dot11FCS].subtype == 8: 
            packet_type = packet[Dot11FCS].type
            packet_subtype = packet[Dot11FCS].subtype
            destination_address = str(packet[Dot11FCS].addr1)
            sender_address = str(packet[Dot11FCS].addr2)
            BSSID = str(packet[Dot11FCS].addr3)
            Channel_freq = str(packet[RadioTap].ChannelFrequency)
            dBm_signal = str(packet[RadioTap].dBm_AntSignal)
            print("PKT_type: %s, PKT_subtype: %s, DA: %s, SA: %s, BSSID: %s, Freq: %s and dBm_signal: %s " %(packet_type, packet_subtype, destination_address, sender_address, BSSID, Channel_freq, dBm_signal))        
        # extract info from packet type management, subtype probe response:                 
        elif packet[Dot11FCS].type == 0  and packet[Dot11FCS].subtype == 5: 
            packet_type = packet[Dot11FCS].type
            packet_subtype = packet[Dot11FCS].subtype
            destination_address = str(packet[Dot11FCS].addr1)
            sender_address = str(packet[Dot11FCS].addr2)
            BSSID = str(packet[Dot11FCS].addr3)
            Channel_freq = str(packet[RadioTap].ChannelFrequency)
            dBm_signal = str(packet[RadioTap].dBm_AntSignal)
            print("PKT_type: %s, PKT_subtype: %s, DA: %s, SA: %s, BSSID: %s, Freq: %s and dBm_signal: %s " %(packet_type, packet_subtype, destination_address, sender_address, BSSID, Channel_freq, dBm_signal))        
        # extract info from packet type extension, subtype 3:                 
        elif packet[Dot11FCS].type == 3  and packet[Dot11FCS].subtype == 3: 
            packet_type = packet[Dot11FCS].type
            packet_subtype = packet[Dot11FCS].subtype
            destination_address = str(packet[Dot11FCS].addr2)
            sender_address = "null"
            BSSID = str(packet[Dot11FCS].addr1)
            Channel_freq = str(packet[RadioTap].ChannelFrequency)
            dBm_signal = str(packet[RadioTap].dBm_AntSignal)
            print("PKT_type: %s, PKT_subtype: %s, DA: %s, SA: %s, BSSID: %s, Freq: %s and dBm_signal: %s " %(packet_type, packet_subtype, destination_address, sender_address, BSSID, Channel_freq, dBm_signal))
        # extract info from packet type management, subtype association response:                 
        elif packet[Dot11FCS].type == 0  and packet[Dot11FCS].subtype == 1: 
            packet_type = packet[Dot11FCS].type
            packet_subtype = packet[Dot11FCS].subtype
            destination_address = str(packet[Dot11FCS].addr2)
            sender_address = "null"
            BSSID = str(packet[Dot11FCS].addr1)
            Channel_freq = str(packet[RadioTap].ChannelFrequency)
            dBm_signal = str(packet[RadioTap].dBm_AntSignal)
            print("PKT_type: %s, PKT_subtype: %s, DA: %s, SA: %s, BSSID: %s, Freq: %s and dBm_signal: %s " %(packet_type, packet_subtype, destination_address, sender_address, BSSID, Channel_freq, dBm_signal))                        
        # extract info from packet type extension, subtype 3:                 
        elif packet[Dot11FCS].type == 0  and packet[Dot11FCS].subtype == 0: 
            packet_type = packet[Dot11FCS].type
            packet_subtype = packet[Dot11FCS].subtype
            destination_address = str(packet[Dot11FCS].addr2)
            sender_address = "null"
            BSSID = str(packet[Dot11FCS].addr1)
            Channel_freq = str(packet[RadioTap].ChannelFrequency)
            dBm_signal = str(packet[RadioTap].dBm_AntSignal)
            print("PKT_type: %s, PKT_subtype: %s, DA: %s, SA: %s, BSSID: %s, Freq: %s and dBm_signal: %s " %(packet_type, packet_subtype, destination_address, sender_address, BSSID, Channel_freq, dBm_signal))                        
        
if __name__ == "__main__":
    # interface name, check using iwconfig:
    interface = "wlan1"
    end = 0
    # enable monitor mode:
    enable_monitor_mode()
        # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    
    # start sniffing for WiFi packets:
    sniff(prn=packet_handler, iface=interface) #, count =20
    end = 1
    