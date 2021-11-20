from scapy.all import *
import datetime
import pymongo
import numpy
from pymongo import MongoClient
import pandas
import time
import os
import serial

    #------- Global Variables --------:

WiFi_frame = pandas.DataFrame(columns=["sniffing session","mac_ids","detection_count","detection_time", "latitude", "longitude"]) # wifi dataframe
WiFi_frame.set_index("sniffing session",inplace=True)

interface = "wlan1"
mac_ids =[]
sniff_session = 0
global detection_count

    #------- GPS --------:
ser = serial.Serial(port = '/dev/ttyUSB0',baudrate = 4800)
ser.flush()

    #------- Mongo Database --------:
host = MongoClient('mongodb+srv://user:password@cluster0.qnb0r.mongodb.net/Database?retryWrites=true&w=majority')
db = host['TaxiService']
collection = db['test_data_dump']

class position:
    def __init__(self,latitude, longitude):
        self.latitude = latitude
        self.longitude = longitude
        
taxi = position(0 , 0)

#...........................................................................................

def packet_handler(packet):
    # function to extract data from captured WiFi packets.
    global detection_count
    
    if packet.haslayer(Dot11):
        addr1 = packet[Dot11].addr1
        addr2 = packet[Dot11].addr2
        if addr1 not in mac_ids:
            mac_ids.append(addr1)
            detection_count+= 1 # increment counter
        if addr2 not in mac_ids:
            mac_ids.append(addr2)
            detection_count+= 1 # increment counter
        

            
#...........................................................................................    

def WiFi_sniff ():
    # function to sniff WiFi MAC address.
    global sniff_session,detection_count
    
    detection_count = 0
    sniff_session += 1
    print("sniff in progress")
    start_time = time.time()
    while ((time.time() - start_time) < 60):
        sniff(prn=packet_handler, iface=interface,count = 10)# sniff for packets
        
    now = datetime.datetime.now()
    date_time = now.strftime("%m/%d/%Y,%H:%M:%S")
    readGPSdata()
    WiFi_frame.loc[sniff_session] = (mac_ids, detection_count, date_time, taxi.latitude, taxi.longitude)
#...........................................................................................

def store_data():
    #Function to store collected data to the database
    global mac_ids
    for i,row in WiFi_frame.iterrows():
        post = {"session_id":i,"mac_ids":row['mac_ids'], "number_of_detected_MAC_ids":row['detection_count'], "date_&_time":row['detection_time'], "latitude":row['latitude'], "longitude":row['longitude']}
        collection.insert_one(post)# store WiFi data to database
    print("data written to DB")   
    WiFi_frame.iloc[0:0]
    del mac_ids
    
#..........................................................................................
    
def enable_monitor_mode():
    
    os.system(f"sudo ifconfig {interface} down")
    os.system(f"sudo iwconfig {interface} mode monitor")
    os.system(f"sudo ifconfig {interface} up")

#..........................................................................................
def readGPSdata():
    GPStime = time.time() # get time
    tempLon = 0
    tempLat = 0
    count = 0
    global taxi
    
    while((time.time() - GPStime)< 5): 
        if(ser.inWaiting() > 0):
            line = ser.readline().decode('utf-8', errors="replace").rstrip()
            data = line.split(",")
            
            if(data[0]=='$GPRMC'):
                if(data[2]=='A'):
                    lat = float(data[3])
                    if (data[4])== 'S':
                        lat *= -1
                    latDEC = int(lat/100) +(lat - ((int(lat/100))*100))/60
                    long = float(data[5])
                    if(data[6])=='W':
                        long *= -1
                    longDEC = int(long/100) +(long - ((int(long/100))*100))/60
                    tempLon += longDEC
                    tempLat += latDEC
                    count += 1
                    
    if (count != 0):
        taxi.latitude = tempLat/count
        taxi.longitude = tempLon/count

                
    
if __name__ == "__main__":
    
    #.................. Variables: ................
    
    detection_count = 0
    sniff_session  = 0
    boot_time = time.time()
    enable_monitor_mode()
    #_______________________________________________________________
    while True: 
        
        if ((time.time() - boot_time)> 180): # sniff
            WiFi_sniff()
            store_data()
            mac_ids = []
    