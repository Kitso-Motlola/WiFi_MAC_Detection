from scapy.all import *
from threading import Thread
from collections import Counter as cnt
import datetime
import time
import os

#____________________________variable:______________________________________

mac_id = []
channel_freq = []
dBm_signal = []
detection_time = []
start_time = []
stop_time = []

#___________________________functions:_______________________________________
def enable_monitor_mode():
    
    os.system(f"sudo ip link set {interface} down")
    os.system(f"sudo iw {interface} set monitor none")
    os.system(f"sudo ip link set {interface} up")


def change_channel():
    channel = 1
    while switch_channel:
        os.system(f"iwconfig {interface} channel {channel}")
        # switch channel from 1 to 14 each 0.5s
        channel = channel % 14 + 1
        time.sleep(0.5)

def packet_handler(packet):
    #function to extract data from captured WiFi packets.
    
    if packet.haslayer(Dot11FCS):
        
        # extract info from packet type control, block ack request:
        if packet[Dot11FCS].type == 1  and packet[Dot11FCS].subtype == 8:
            addr1 = str(packet[Dot11FCS].addr1)
            addr2 = str(packet[Dot11FCS].addr2)
            freq = str(packet[RadioTap].ChannelFrequency)
            dBm = str(packet[RadioTap].dBm_AntSignal)
            time = datetime.datetime.now()
            #insert information into data collection:
            if addr1 not in mac_id :
                mac_id.append(addr1)
                channel_freq.append(freq)
                dBm_signal.append(dBm)
                detection_time.append(time)
                # add the other mac address:
                if addr2 not in mac_id:
                    mac_id.append(addr2)
                    channel_freq.append(freq)
                    dBm_signal.append(dBm)
                    detection_time.append(time)
                    
        # extract info from packet type management, subtype action:    
        elif packet[Dot11FCS].type == 0  and packet[Dot11FCS].subtype == 13:
            addr1 = str(packet[Dot11FCS].addr1)
            addr2 = str(packet[Dot11FCS].addr2)
            freq = str(packet[RadioTap].ChannelFrequency)
            dBm = str(packet[RadioTap].dBm_AntSignal)
            time = datetime.datetime.now()
            #insert information into data collection:
            if addr1 not in mac_id :
                mac_id.append(addr1)
                channel_freq.append(freq)
                dBm_signal.append(dBm)
                detection_time.append(time)
                # add the other mac address:
                if addr2 not in mac_id:
                    mac_id.append(addr2)
                    channel_freq.append(freq)
                    dBm_signal.append(dBm)
                    detection_time.append(time)
                    
        # extract info from packet type management, subtype reassociation response:                 
        elif packet[Dot11FCS].type == 0  and packet[Dot11FCS].subtype == 3:
            addr1 = str(packet[Dot11FCS].addr1)
            addr2 = str(packet[Dot11FCS].addr2)
            freq = str(packet[RadioTap].ChannelFrequency)
            dBm = str(packet[RadioTap].dBm_AntSignal)
            time = datetime.datetime.now()
            #insert information into data collection:
            if addr1 not in mac_id :
                mac_id.append(addr1)
                channel_freq.append(freq)
                dBm_signal.append(dBm)
                detection_time.append(time)
                # add the other mac address:
                if addr2 not in mac_id:
                    mac_id.append(addr2)
                    channel_freq.append(freq)
                    dBm_signal.append(dBm)
                    detection_time.append(time)

                    
        # extract info from packet type extension, subtype 2:                 
        elif packet[Dot11FCS].type == 3  and packet[Dot11FCS].subtype == 2:
            addr1 = str(packet[Dot11FCS].addr1)
            addr2 = str(packet[Dot11FCS].addr2)
            freq = str(packet[RadioTap].ChannelFrequency)
            dBm = str(packet[RadioTap].dBm_AntSignal)
            time = datetime.datetime.now()
            #insert information into data collection:
            if addr1 not in mac_id :
                mac_id.append(addr1)
                channel_freq.append(freq)
                dBm_signal.append(dBm)
                detection_time.append(time)
                # add the other mac address:
                if addr2 not in mac_id:
                    mac_id.append(addr2)
                    channel_freq.append(freq)
                    dBm_signal.append(dBm)
                    detection_time.append(time)
                    
        # extract info from packet type data, subtype null:                 
        elif packet[Dot11FCS].type == 2  and packet[Dot11FCS].subtype == 4:
            addr1 = str(packet[Dot11FCS].addr1)
            addr2 = str(packet[Dot11FCS].addr2)
            freq = str(packet[RadioTap].ChannelFrequency)
            dBm = str(packet[RadioTap].dBm_AntSignal)
            time = datetime.datetime.now()
            #insert information into data collection:
            if addr1 not in mac_id :
                mac_id.append(addr1)
                channel_freq.append(freq)
                dBm_signal.append(dBm)
                detection_time.append(time)
                # add the other mac address:
                if addr2 not in mac_id:
                    mac_id.append(addr2)
                    channel_freq.append(freq)
                    dBm_signal.append(dBm)
                    detection_time.append(time)
                    
        # extract info from packet type management, subtype probe request:                 
        elif packet[Dot11FCS].type == 0  and packet[Dot11FCS].subtype == 4:
            addr1 = str(packet[Dot11FCS].addr1)
            addr2 = str(packet[Dot11FCS].addr2)
            freq = str(packet[RadioTap].ChannelFrequency)
            dBm = str(packet[RadioTap].dBm_AntSignal)
            time = datetime.datetime.now()
            #insert information into data collection:
            if addr1 not in mac_id :
                mac_id.append(addr1)
                channel_freq.append(freq)
                dBm_signal.append(dBm)
                detection_time.append(time)
                # add the other mac address:
                if addr2 not in mac_id:
                    mac_id.append(addr2)
                    channel_freq.append(freq)
                    dBm_signal.append(dBm)
                    detection_time.append(time)
                    
        # extract info from packet type management, subtype authentication:                 
        elif packet[Dot11FCS].type == 0  and packet[Dot11FCS].subtype == 11:
            addr1 = str(packet[Dot11FCS].addr1)
            addr2 = str(packet[Dot11FCS].addr2)
            freq = str(packet[RadioTap].ChannelFrequency)
            dBm = str(packet[RadioTap].dBm_AntSignal)
            time = datetime.datetime.now()
            #insert information into data collection:
            if addr1 not in mac_id :
                mac_id.append(addr1)
                channel_freq.append(freq)
                dBm_signal.append(dBm)
                detection_time.append(time)
                # add the other mac address:
                if addr2 not in mac_id:
                    mac_id.append(addr2)
                    channel_freq.append(freq)
                    dBm_signal.append(dBm)
                    detection_time.append(time)
                    
        # extract info from packet type management, subtype beacon:                 
        elif packet[Dot11FCS].type == 0  and packet[Dot11FCS].subtype == 8:
            addr1 = str(packet[Dot11FCS].addr1)
            addr2 = str(packet[Dot11FCS].addr2)
            freq = str(packet[RadioTap].ChannelFrequency)
            dBm = str(packet[RadioTap].dBm_AntSignal)
            time = datetime.datetime.now()
            #insert information into data collection:
            if addr1 not in mac_id :
                mac_id.append(addr1)
                channel_freq.append(freq)
                dBm_signal.append(dBm)
                detection_time.append(time)
                # add the other mac address:
                if addr2 not in mac_id:
                    mac_id.append(addr2)
                    channel_freq.append(freq)
                    dBm_signal.append(dBm)
                    detection_time.append(time)
                           
        # extract info from packet type management, subtype probe response:                 
        elif packet[Dot11FCS].type == 0  and packet[Dot11FCS].subtype == 5:
            addr1 = str(packet[Dot11FCS].addr1)
            addr2 = str(packet[Dot11FCS].addr2)
            freq = str(packet[RadioTap].ChannelFrequency)
            dBm = str(packet[RadioTap].dBm_AntSignal)
            time = datetime.datetime.now()
            #insert information into data collection:
            if addr1 not in mac_id :
                mac_id.append(addr1)
                channel_freq.append(freq)
                dBm_signal.append(dBm)
                detection_time.append(time)
                # add the other mac address:
                if addr2 not in mac_id:
                    mac_id.append(addr2)
                    channel_freq.append(freq)
                    dBm_signal.append(dBm)
                    detection_time.append(time)
                          
        # extract info from packet type extension, subtype 3:                 
        elif packet[Dot11FCS].type == 3  and packet[Dot11FCS].subtype == 3:
            addr1 = str(packet[Dot11FCS].addr1)
            addr2 = str(packet[Dot11FCS].addr2)
            freq = str(packet[RadioTap].ChannelFrequency)
            dBm = str(packet[RadioTap].dBm_AntSignal)
            time = datetime.datetime.now()
            #insert information into data collection:
            if addr1 not in mac_id :
                mac_id.append(addr1)
                channel_freq.append(freq)
                dBm_signal.append(dBm)
                detection_time.append(time)
                # add the other mac address:
                if addr2 not in mac_id:
                    mac_id.append(addr2)
                    channel_freq.append(freq)
                    dBm_signal.append(dBm)
                    detection_time.append(time)
                    
        # extract info from packet type management, subtype association response:                 
        elif packet[Dot11FCS].type == 0  and packet[Dot11FCS].subtype == 1: 
            addr1 = str(packet[Dot11FCS].addr1)
            addr2 = str(packet[Dot11FCS].addr2)
            freq = str(packet[RadioTap].ChannelFrequency)
            dBm = str(packet[RadioTap].dBm_AntSignal)
            time = datetime.datetime.now()
            #insert information into data collection:
            if addr1 not in mac_id :
                mac_id.append(addr1)
                channel_freq.append(freq)
                dBm_signal.append(dBm)
                detection_time.append(time)
                # add the other mac address:
                if addr2 not in mac_id:
                    mac_id.append(addr2)
                    channel_freq.append(freq)
                    dBm_signal.append(dBm)
                    detection_time.append(time)

        # extract info from packet type extension, subtype 3:                 
        elif packet[Dot11FCS].type == 0  and packet[Dot11FCS].subtype == 0:
            addr1 = str(packet[Dot11FCS].addr1)
            addr2 = str(packet[Dot11FCS].addr2)
            freq = str(packet[RadioTap].ChannelFrequency)
            dBm = str(packet[RadioTap].dBm_AntSignal)
            time = datetime.datetime.now()
            #insert information into data collection:
            if addr1 not in mac_id :
                mac_id.append(addr1)
                channel_freq.append(freq)
                dBm_signal.append(dBm)
                detection_time.append(time)
                # add the other mac address:
                if addr2 not in mac_id:
                    mac_id.append(addr2)
                    channel_freq.append(freq)
                    dBm_signal.append(dBm)
                    detection_time.append(time)

                        
#___________________________________________________________________________________________
    
        
if __name__ == "__main__":
    
    # Locally utilised variables:
    interface = "wlan1"
    switch_channel = True # channel switching variable
    vehicle_stopped = True # flag to show if vehicle stopped
    print_counter = 0 # printing variable
#.............................................................
    
    enable_monitor_mode()
    # start channel changing functions
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
#............................................................
    start_time = time.time()
#............................................................    
    
    while True: #infinite loop for control system:
        print("infinite loop active")
        if vehicle_stopped: # vehicle stopped??
            print("vehicle stopped")
            vehicle_stopped = False # reset vehicle stationery state flag
            WiFi_timer = time.time() # store current time
            while((time.time()- WiFi_timer)< 60): # start WiFi packet sniffing for 1 mins:
                sniff(prn=packet_handler, iface=interface,count = 10)
                print("sniffing...")
                
            # start bluetooth sniffing
            # implement RF idenfication
            # fetch USSD information
            # show detected passanger
            while print_counter < len(mac_id):
                print("MAC_id: %s , freq: %s Hz, signal_strength: %s dBm & time: %s" %(mac_id[print_counter],channel_freq[print_counter],dBm_signal[print_counter],detection_time[print_counter]))
                print_counter = print_counter + 1 # printing increment counter
                
        break
    
    
    

    
