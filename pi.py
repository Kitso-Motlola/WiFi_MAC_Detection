# Software developed to be executed by a raspberry pi 3 B +
# Requires installation of the following software & libraries :
#    1) Scapy
#    2) Paho.Mqtt
#    3) pymongo
#    4) Pandas
# Software is written by : Kitso Motlola
#_____________________________________________________________________________________-
from scapy.all import *
import paho.mqtt.client as mqtt
import datetime
import random
import time
import pymongo
from pymongo import MongoClient
import pandas
#____________________________variables:______________________________________

interface = "wlan1"

    
        #----------- WiFi data ------:
    
WiFi_frame = pandas.DataFrame(columns=["mac_id","detection_time"])
WiFi_frame.set_index("mac_id",inplace=True)
    
        #----------- GPS data ------:
    
GPSdata = pandas.DataFrame(columns=["time","latitude","longitude"])
GPSdata.set_index("time",inplace=True)

    #------- Mongo Database --------:

print("mongo setup")
host = MongoClient('mongodb+srv://user:password@cluster0.qnb0r.mongodb.net/Database?retryWrites=true&w=majority')
db = host['TaxiService']
collection = db['data_dump']
#...........................................................................................

def packet_handler(packet):
    # function to extract data from captured WiFi packets.
    if packet.haslayer(Dot11):
        mac_id = packet[Dot11].addr1
        ssid = packet[Dot11].addr2
        now = datetime.datetime.now()
        date_time = now.strftime("%m/%d/%Y,%H:%M:%S")
        WiFi_frame.loc[mac_id]=(date_time)
        if (mac_id != ssid):
            WiFi_frame.loc[ssid]=(date_time)
#...........................................................................................    

def WiFi_sniff ():
    # function to sniff WiFi MAC address.
    start_time = time.time()
    while ((time.time() - start_time) < 10):
        sniff(prn=packet_handler, iface=interface,count = 10)# sniff for packets
#...........................................................................................

def store_data():
    #Function to store collected data to the database
    for i,row in WiFi_frame.iterrows():
        post = {"mac_id":i,"time":row['detection_time']}
        collection.insert_one(post)# store WiFi data to database
        
    #WiFi_frame = WiFi_frame.drop(WiFi_frame[WiFi_frame.detection_time != ""].index)  
    #--------------------------------------------------------------------------------------
#...........................................................................................
        
def getGPSdata():
    #function to retrieve GPS data from USB

    data = open("output.nmea","r")
    #iterate trough the read lines and split into an array using the comma (',') delimiter :
    for line in data:
        gps_data = line.split(',')
    
        #extract the latitude and longitude:
        if(gps_data[0]=='$GPRMC'):
        
        #only evaluate valid data:
            if(gps_data[2]=='A'): 
                #perform the latitude calculation:
                latGPS = float(gps_data[3])
                if(gps_data[4])=='S':
                    latGPS *= -1
                #conversion to decimal degrees:
                latDEC = int(latGPS/100) +(latGPS - ((int(latGPS/100))*100))/60
                #perform the longitude calculation:
                lonGPS = float(gps_data[5])
                if(gps_data[6])=='W':
                    lonGPS *= -1
                #conversion to decimal degrees:
                lonDEC = int(lonGPS/100) +(lonGPS - ((int(lonGPS/100))*100))/60
                now = datetime.datetime.now()
                date_time = now.strftime("%m/%d/%Y,%H:%M:%S")
                print(str(date_time)+" : "+str(lonDEC)+" , "+str(lonGPS))
                GPSdata.loc[date_time] = (lonDEC,latDEC)
                time.sleep(2) # replace with something else
    # Close the file after reading relevant data:
    data.close()
    print(GPSdata)

#...........................................................................................
    
def on_connect(client, userdata, flags, rc):
    #Paho MQTT connection callback function
    if rc == 0:
        print("Connection successful")
    else:
        print("Connection failed, error code :" + rc)
#..........................................................................................
        
def on_publish(client, userdata, result):
    #Paho MQTT publish callback function
    if result == 0:
        print("Publish  Successful")
    else:
        print("Detected error, code :" + str(result))
#.........................................................................................
        
def on_message(client,userdata, msg):
    #Paho MQTT message callback function
    print(msg.payload.decode("utf-8"))
#........................................................................................
    
def MQTT_send():
    # function to send data through MQTT
    for i,row in WiFi_frame.iterrows():
        message = "mac_id: "+ i + ";" +" time: "+row['detection_time']
        client.publish("test/run", message, qos = 2)# send message
#___________________________________________________________________________________________
    
        
if __name__ == "__main__":
    
    #.................. Variables: ................

    
        #----------- MQTT client ------:
    
    client = mqtt.Client()
    client.tls_set(tls_version=mqtt.ssl.PROTOCOL_TLS)
    client.username_pw_set("username","password")
    client.on_connect = on_connect
    client.on_publish = on_publish
    client.on_message = on_message
    client.connect("02da3665b971428483f6020a030bf13c.s1.eu.hivemq.cloud",8883)
    client.subscribe("test/run")
    
        #----------- Timer ------:
    
    boot_time = time.time()
    print("in front of loop")
    palo = 0

    #_______________________________________________________________
    while True: #infinite loop for control system:
        
        if ((time.time() - boot_time)> 30): # sniff 
            WiFi_sniff()
            store_data()
            palo = palo + 1
            
        if (palo > 15):
            break
    
    