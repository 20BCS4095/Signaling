import base64
from queue import SimpleQueue
from flask import Flask, json, request, render_template, Response
import datetime
import requests
from enum import IntEnum
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import time
import threading
import logging
import random
import hashlib
import subprocess
import binascii
import random
from tabulate import tabulate
app = Flask(__name__)

logger1 = logging.getLogger('logger1')
logger1.setLevel(logging.DEBUG)
file_handler1 = logging.FileHandler('logfile1.log')
formatter = logging.Formatter('[%(asctime)s] - %(message)s')
file_handler1.setFormatter(formatter)
logger1.addHandler(file_handler1)
random_ack=0
num_keys =0
EtagLast=''
EtagPresent='0'
last_request_time = 0
last_response_time=0
printer_status="Not started to polling"
duration_set_bit=  {
    "start_tunnel_1": 0,
    "start_tunnel_2": 0,
    "start_tunnel_3": 0,
    "start_tunnel_4": 0,
    "echo": 0,
    "rtp_kick": 0,
    "fw_update": 0,
    "registration_subscription": 0,
    "cdm_pubsub_1": 0,
    "cdm_pubsub_2": 0,
    "cdm_pubsub_3": 0,
    "connectivity_configuration": 0,
    "device_configuration": 0
}
duration_ack_bit = {
    "start_tunnel_1": 0,
    "start_tunnel_2": 0,
    "start_tunnel_3": 0,
    "start_tunnel_4": 0,
    "echo": 0,
    "rtp_kick": 0,
    "fw_update": 0,
    "registration_subscription": 0,
    "cdm_pubsub_1": 0,
    "cdm_pubsub_2": 0,
    "cdm_pubsub_3": 0,
    "connectivity_configuration": 0,
    "device_configuration": 0
}
set_signal_data = []
reset_signal_data = []
update_config_data = {
'PrinterID':'0.0.0.0',
'CollectionID': '',
'Descriptor':'',
'SignatureKey':'',
'ProtocolSwitchingPolicy': '',
'PollingDelay': 0,
'PollingTimeout':'',
'RetryGraceCount': '',
'RandomWindow':0,
'PrinterStatusRatio': '',
'MaxGetsBetweenPosts': '',
'URL': ''
}
old_config_data={ 
'PrinterIP':'',
'CollectionID': '',
'Descriptor':'',
'SignatureKey':'',
'ProtocolSwitchingPolicy': '',
'PollingDelay': 0,
'PollingTimeout':'',
'RetryGraceCount': '',
'RandomWindow':0,
'PrinterStatusRatio': '',
'MaxGetsBetweenPosts': '',
'URL': ''
}
printer_time=0
simulator_time=0
reset_signaling_data = {}
stored_binary_data = b''
success_frame = b''
error_frame = b''
critical_error_frame = b''
encrypted_data=b''
stored_binary =b''
aad=b''
nonce=b''
durationTest=True
completeDuration=False
duration_hours=0
plaintext=b''
collectionId=''
Descriptor=''
range_count=0
out_count=0
set_count=0
reset_count=0
signaling_set_by_server=0
signaling_ack_by_server=0
configuration_change=""
HEADER_MASK = 0xF8
HEADER_LEN_MASK = 0x07
TLV_BIG = 0x06
TLV_EXTRA_BYTE = 0x07
TLV_BIG_LEN_IN_BITS = 0xFE
TLV_EXTRA_BYTE_LEN_IN_BYTES = 0xFD
GCM_TAG_LEN = 12
SUPPORTED_MAJOR_VERSION = 2
SUPPORTED_MINOR_VERSION = 0
SIG_NONCE_LEN = 4
printer_simulator="NO"
index = 0
collection=0
Values={
'Version':'2.0',
'Command':'',
'CollectionId':'',
'Nonce':'',
'TimeStamp':'',
'EncryptedBlock':'',
'EnhancedGcm':'',
'CloudPrinterId':'',
'Descriptor':'',
'PrinterStatus':'',
'AppFlagAsk':b'\x00\x00',
'AppFlagAskSignal':'',
'CurrentReplyTime':''
}
BinaryValues={
'CollectionId':b'',
'Nonce':b'',
'TimeStamp':b'',
'EncryptedBlock':b'',
'EnhancedGcm':b'',
'aad':b'',
'tag':b'',
'ciphertext':b'',
'IV':b''
}

AppFlagAsk={ 
}

set_signaling_values = {
'start_tunnel_1': 0,
'start_tunnel_2': 0,
'start_tunnel_3':0,
'start_tunnel_4': 0,
'echo': 0,
'rtp_kick': 0,
'fw_update': 0,
'registration_subscription': 0,
'cdm_pubsub_1':0,
'cdm_pubsub_2': 0,
'cdm_pubsub_3': 0,
'connectivity_configuration': 0,
'device_configuration': 0,
}
reset_signaling_values={
   1:'start_tunnel_1',
   2:'start_tunnel_2',
   3:'start_tunnel_3',
   4:'start_tunnel_4',
   5:'echo',
   6:'rtp_kick',
   7:'fw_update',
   8:'registration_subscription',
   9:'cdm_pubsub_1',
   10:'cdm_pubsub_2',
   11:'cdm_pubsub_3',
   12:'connectivity_configuration',
   13:'device_configuration'
}
Signaling_variables ={
'Start Tunnel 1':0,
'Start Tunnel 2':0,
'Start Tunnel 3':0,
'Start Tunnel 4':0,
'Echo ':0,
'Rtp Kick ':0,
'Fw Update ':0,
'Registration Subscription ':0,
'Cdm Pub Sub 1':0,
'Cdm Pub Sub 2':0,
'Cdm Pub Sub 3':0,
'Connectivity Configuration ':0,
'Device Configuration ':0,
}

def check_printer_status():
    global last_request_time
    global printer_status
    while True:
        if time.time() - last_request_time > 60:
            printer_status="Printer is offline"
        else:
            printer_status="Printer is online"
        time.sleep(5)

def clear_logs(log_file):
    with open(log_file, 'w') as f:
        f.truncate(0)
    print("Logs cleared successfully.")

def repeat_function(duration, logger1):
    global durationTest,completeDuration,signaling_set_by_server,update_config_data,old_config_data,duration_set_bit,duration_ack_bit
    global set_signaling_values,random_ack,num_keys 
    global reset_count,set_count
    logger1.info('--------------------------------Duration Testing Start-----------------------------------------------\n')
    start_time = time.time()
    end_time =start_time +duration
    options=["start_tunnel_1","start_tunnel_2","start_tunnel_3","start_tunnel_4","echo","rtp_kick","fw_update","registration_subscription","cdm_pubsub_1","cdm_pubsub_2","cdm_pubsub_3","connectivity_configuration","device_configuration"]
    logger1.info('                                         SET BIT                                              ')
    while time.time() < end_time-120:
        if durationTest:
           num_keys = random.randint(1,2)
           random_keys = random.sample(options, num_keys)
           random_ack=0
           for key in random_keys:
              set_signaling_values[key] = 1
              duration_set_bit[key]+=1
              set_count += 1
              signaling_set_by_server+=1
              logger1.info(f'Set bit -> {key}')
        if num_keys==2 and random_ack==2:
            time.sleep(60)
            durationTest=True
        elif num_keys==1 and random_ack==1:
            time.sleep(60)
            durationTest=True
        else:
            durationTest=False
    time.sleep(60)
    old_config_data=update_config_data
    logger1.info('\n')
    logger1.info('                                    Update Configuration                                                ')
    update_config_data = {
            'PrinterID':old_config_data['PrinterID'],
            'CollectionID': "5678",
            'Descriptor': "900",
            'SignatureKey':"SDTH34vvWThjTH45",
            'ProtocolSwitchingPolicy': "httpOnly",
            'PollingDelay': 20,
            'PollingTimeout': 17,
            'RetryGraceCount': 13,
            'RandomWindow':4,
            'PrinterStatusRatio': 12,
            'MaxGetsBetweenPosts': 3,
            'URL':"http://15.77.12.114:5000//server"
        }
    thread3=threading.Thread(target=update_configuration_data, args=(update_config_data,))
    thread3.start()
    logger1.info(f'Update the configuration to check Printer Applying that')
    logger1.info(f'Old Configuration -> {old_config_data}')
    logger1.info(f'Get the configuration from printer')
    config_thread= threading.Thread(target=get_update_configuration)
    config_thread.start()
    configuration_change=config_thread
    printsimulatorthread=threading.Thread(target=printertime_simulatortime)
    printsimulatorthread.start()
    if configuration_change=='':
        logger1.info(f'Printer Applying the Configuration -> NO')
    else:
     logger1.info(f'Printer Applying the Configuration -> YES')
    
    logger1.info(f'New Configuration -> {update_config_data}\n')
    logger1.info('                                          Metrics                                                            ')
    status_thread = threading.Thread(target=check_printer_status)
    status_thread.start()
    logger1.info(f'Printer Status -> {printer_status}')
    epoch_time=last_request_time
    normal_time = datetime.datetime.utcfromtimestamp(epoch_time)
    m=normal_time.strftime('%Y-%m-%d %H:%M:%S')
    logger1.info(f'Printer Last Seen -> {m}')
    logger1.info(f'Simulator time vs Printer time -> {printer_simulator}')
    logger1.info(f'Polling Frequency Count between range -> {range_count}')
    logger1.info(f'Out range count -> {out_count}')
    time.sleep(60)
    logger1.info('-----------------------------------------------Duration test completed------------------------------------------------------------')
    logger1.info(f'Total no of bit set by server -> {set_count}')
    logger1.info(f'Total no of bit ack -> {reset_count}')
    combined_data = [(key, duration_set_bit[key], duration_ack_bit[key]) for key in duration_set_bit]
    logger1.info('-------------------------------------------------Set bit vs Ack bit----------------------------------------------------------------')
    headers = ["Key", "Set bit Count 1", "Ack bit Count 2"]

    table = tabulate(combined_data, headers, tablefmt="solid")
    logger1.info("\n" + table)
    completeDuration=True

def update_configuration_data(update_config):
   base_url = "http://"+str(update_config['PrinterID'])+"/hp/device/WSFramework/underware/v1/command"
   command2="Signaling PUB_setHttpSignalingConfig "+str(update_config["PollingDelay"])+" "+str(update_config["PollingTimeout"])+" "+str(update_config["RetryGraceCount"])+" "+str(update_config["RandomWindow"])+" "+str(update_config["PrinterStatusRatio"])+" "+str(update_config["MaxGetsBetweenPosts"])+" "+str(update_config["URL"])
   request_body = {
           "version": "1.0.0",
           "targetService": "mainApp",
           "blocking": "true",
           "encoding": "text",
           "command": command2
        }
   data1=json.dumps(request_body)
   response = requests.post(base_url, data=data1)
   print(response)
   command1="Signaling PUB_setSignalingConfig "+str(update_config["CollectionID"])+" "+str(update_config["Descriptor"])+" "+str(update_config["SignatureKey"])+" "+str(update_config["ProtocolSwitchingPolicy"])
   request_body = {
    "version": "1.0.0",
    "targetService": "mainApp",
    "blocking": "true",
    "encoding": "text",
    "command": command1
    }
   json_data=json.dumps(request_body)
   response = requests.post(base_url,data=json_data)
   print(response)

def get_update_configuration():
    global configuration_change,printer_time,printer_simulator
    base_url = "http://"+str(update_config_data['PrinterID'])+"/hp/device/WSFramework/underware/v1/command"
    command1="Signaling PUB_printProtocolConfig"
    request_body = {
    "version": "1.0.0",
    "targetService": "mainApp",
    "blocking": "true",
    "encoding": "text",
    "command": command1
    }
    json_data=json.dumps(request_body)
    response = requests.post(base_url,data=json_data)
    data = response.json()
    decoded_resp = base64.b64decode(data['response'])
    new_string = decoded_resp.decode('utf-8')
    collection_id= new_string[new_string.find("Collection Id ")+len("Collection Id "): new_string.find("Descriptor ")]
    index = new_string.find("Descriptor ")
    length=len("Descriptor ")
    descriptor= new_string[index+length:new_string.find("Signature_key ")]
    index = new_string.find("Signature_key ")
    length=len("Signature_key ")
    signature_key= new_string[index+length:new_string.find("Protocol Switching Policy ")]
    index = new_string.find("Protocol Switching Policy ")
    length=len("Protocol Switching Policy ")
    protocol_switching_policy= new_string[index+length:new_string.find("udp_polling - polling_timeout ")]
    polling_timeout= int(new_string[new_string.find("http_polling - polling_timeout ")+len("http_polling - polling_timeout "):new_string.find("http_polling - polling_delay ")])
    polling_delay = int(new_string[new_string.find("http_polling - polling_delay ")+len("http_polling - polling_delay "): new_string.find("http_polling - retry_grace_count ")])
    retry_grace_count= int(new_string[new_string.find("http_polling - retry_grace_count ")+len("http_polling - retry_grace_count "):new_string.find("http_polling - random_window ")])
    random_window = int(new_string[new_string.find("http_polling - random_window ")+len("http_polling - random_window "):new_string.find("http_polling - printer_status_ratio ")])
    printer_status_ratio = int(new_string[new_string.find("http_polling - printer_status_ratio ")+len("http_polling - printer_status_ratio "):new_string.find("http_polling - max_gets_between_posts ")])
    max_gets_between_posts = int(new_string[new_string.find("http_polling - max_gets_between_posts ")+len("http_polling - max_gets_between_posts "):new_string.find("http_polling - url ")])
    url = new_string[new_string.find("http_polling - url ")+len("http_polling - url "):]
    if collection_id.strip()== update_config_data['CollectionID'] and descriptor.strip()==update_config_data['Descriptor'] and signature_key.strip()==update_config_data['SignatureKey'] and protocol_switching_policy.strip()==update_config_data['ProtocolSwitchingPolicy'] and polling_delay== int(update_config_data['PollingDelay']) and polling_timeout==int(update_config_data['PollingTimeout']) and retry_grace_count==int(update_config_data['RetryGraceCount']) and random_window == int(update_config_data['RandomWindow']) and printer_status_ratio== int(update_config_data['PrinterStatusRatio'])and max_gets_between_posts==int(update_config_data['MaxGetsBetweenPosts']) and url.strip()==update_config_data['URL']:
        return "Yes"
    else:
        configuration_change=""
        return ""

def printertime_simulatortime():
    global configuration_change,printer_time,printer_simulator
    base_url = "http://"+str(update_config_data['PrinterID'])+"/hp/device/WSFramework/underware/v1/command"
    command2 ="RealTimeClockConfig getHpClock"
    request_body = {
    "version": "1.0.0",
    "targetService": "mainApp",
    "blocking": "true",
    "encoding": "text",
    "command": command2
    }
    json_data=json.dumps(request_body)
    response = requests.post(base_url,data=json_data)
    data = response.json()
    printer_time=int(base64.b64decode(data['response']))
    if simulator_time-120<=printer_time or simulator_time>=printer_time-120:
        printer_simulator="Yes Printer apply simulator time"
    else:
        printer_simulator= "NO Printer doesn't apply simulator time"

class Version():
    major=SUPPORTED_MAJOR_VERSION
    minor=SUPPORTED_MINOR_VERSION

class Variable(IntEnum):
    Null = 0
    Version = 1
    CollectionId = 2
    Command = 3
    ReturnCode = 4
    CloudPrinterId = 6
    DeviceDescriptor = 7
    TimeStamp = 8 
    EpochTimeCurrReply=9
    CollectionContent = 11
    AppFlags = 12
    PrinterStatus = 13
    ReplyExpiration = 14
    SignatureGcm  = 15
    EncryptedBlock = 16
    Padding = 17
    AppFlagsAck = 18
    Nonce = 19
    EnhanceGcm = 20

class ReturnCode(IntEnum):
    Ok = 0x1
    NoUpdate = 0x2
    SyntaxError = 0x81
    SignatureMismatch = 0x82
    VersionUnsupported = 0x83
    CollectionUnknown = 0x84
    ServerUnavailable = 0x85

class Commands(IntEnum):
    Reserved = 0x0
    GetCollection = 0x1
    ChangePollingFreq = 0x2
    ChangeRetryGraceCnt = 0x3

class ApplicationType(IntEnum):
    start_tunnel_1 = 0
    start_tunnel_2 = 1
    start_tunnel_3 = 2
    start_tunnel_4 = 3
    echo = 4
    rtp_kick = 5
    fw_update = 6
    registration_subscription = 7
    cdm_pubsub_1 = 8
    cdm_pubsub_2 = 9
    cdm_pubsub_3 = 10
    connectivityConfig =11
    device_configuration = 12

class SignalingData:
    VariableLengthLimits_ = {
        Variable.Null:                     (0, 0),
        Variable.Version:                  (1, 2),
        Variable.CollectionId:            (4, 16),
        Variable.Command:                 (5, 17),
        Variable.ReturnCode:              (1, 1),
        Variable.CloudPrinterId:          (32, 48),
        Variable.DeviceDescriptor:         (4, 8),
        Variable.TimeStamp:               (5, 5), 
        Variable.EpochTimeCurrReply:         (5,5),
        Variable.CollectionContent:       (400,512),
        Variable.AppFlags:                (5,16),
        Variable.PrinterStatus:           (5, 6),
        Variable.EncryptedBlock:          (512, 1024),
        Variable.Padding:                 (16, 32),
        Variable.AppFlagsAck:             (5, 16),
        Variable.Nonce:                  (4, 32),
        Variable.EnhanceGcm:             (16, 32),
        Variable.ReplyExpiration:        (2,4),
        Variable.SignatureGcm:            (12,32)
    }

    @staticmethod
                   
    def encode_tlv(name, length):  
        tlv = 0
        if length <= SignalingData.VariableLengthLimits_[name][1]:
            if length <= 5:
                tlv_small = length
                tlv = ((name << 3) | tlv_small)
            else:
                tlv = ((name << 3) | TLV_BIG)
        return tlv
    
    def convert_to_bytes(key):
        bytes_data = str.encode(key)
        return bytes_data

    def gcm_parameter(signatureKey):
        key=SignalingData.convert_to_bytes(signatureKey)
        nonce=BinaryValues['IV']
        ciphertext=BinaryValues['ciphertext']
        tag=BinaryValues['tag']
        aad=BinaryValues['aad']
        return key,nonce,ciphertext,tag,aad

    def decode_Tlv(tlv):
        var_name = (tlv & HEADER_MASK) >> 3
        if tlv & HEADER_LEN_MASK == TLV_BIG:
            length = TLV_BIG_LEN_IN_BITS
        elif tlv & HEADER_LEN_MASK == TLV_EXTRA_BYTE:
            length = TLV_EXTRA_BYTE_LEN_IN_BYTES
        else:
            length = tlv & HEADER_LEN_MASK
        return length,var_name
        
    def convert_decimaltohexabinary(stored):
        request_value = [char for char in stored]
        request_data = ' '.join(map(str, request_value))
        bytes_list = request_data.split()
        byte_values = [int(byte_str) for byte_str in bytes_list]
        binary_data = bytes(byte_values)
        return binary_data
    
    def aes_gcm_encrypt(key, nonce, plaintext, aad):
        backend=default_backend()
        cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=backend
        )
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag[:12]
        return (ciphertext, tag)
    
    def aes_gcm_decrypt(key, nonce, ciphertext, tag, aad):
        backend=default_backend()
        cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag, min_tag_length=12),
        backend=backend
        )
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    
    def convert_to_bytes(key):
        bytes_data = str.encode(key)
        return bytes_data
    
    def appFlagSet():
        a=7
        output={}
        b=0
        binary='00000000'
        for key,values in list(set_signaling_values.items())[:8]:
            if values==1 and a>=0:
                output[b]=(int(binary[0:a]+'1'+binary[a:7],2))
                a=a-1
            else:
                output[b]=(int('0',2))
                a=a-1
            b=b+1
        a=5
        for key,values in list(set_signaling_values.items())[8:]:
            if values ==1 and a>=0:
                output[b]=(int(binary[0:a]+'1'+binary[a:5],2))
                a=a-1
            else:
               output[b]=(int('0',2))
               a=a-1
            b=b+1
        return output
        
    def collectionBitmap(descriptor):
       ascii=[]
       last=128
       first=int(descriptor/8)-1
       byte=int(descriptor%8)
       lastvalue=128-int(descriptor/8)-2
       firstBool=True
       middleBool=True
       lastBool=True
       while last>0:
        if firstBool:
            if first>=0 and first<64:
                ascii.append(first)
            elif first>=64:
                ascii.append(192)
                ascii.append(0)
                ascii.append(first)
            last=last-first
            firstBool=False
            middleBool=True
        elif middleBool:
            if descriptor!=0:
                last -=1
                ascii.append(128)
                msb_position = byte
                value = 1 << msb_position
                ascii.append(value)
            middleBool=False
            lastBool=True
        elif lastBool:
            if descriptor%8==0:
                lastvalue+=1
            if lastvalue>=0 and lastvalue<64:
                ascii.append(lastvalue)
            elif lastvalue>=64:
                ascii.append(192)
                ascii.append(0)
                ascii.append(lastvalue)
            lastBool=False
            last=0
       return ascii
        
    def setCollectionContent(key1,value):
        hex_bytes = Values['AppFlagAsk']
        reversed_bytes=hex_bytes[0:1:]
        binary_string = ''.join(format(byte, '08b') for byte in reversed_bytes)
        reversed_binary_string = binary_string[::-1] 
        reversed_bytes=hex_bytes[1:2:]
        binary_string = ''.join(format(byte, '08b') for byte in reversed_bytes)
        reversed_binary_string+=binary_string[::-1]
        binary_array1 = {}
        output={}
        c=0
        b=0
        binary='00000000'
        for bit in reversed_binary_string:
          binary_array1[c]=(int(bit))
          AppFlagAsk[c]=(int(bit))
          c=c+1
        a=7
        for key ,values in list(binary_array1.items())[:8]:
           if values==1 and a>=0:
             output[b]=(int(binary[0:a]+'1'+binary[a:7],2))
           else:
             output[b]=(int('0',2))
           a=a-1
           b=b+1
        a=5
        for key, values in list(binary_array1.items())[8:]:
           if values ==1 and a>=0:
            output[b]=(int(binary[0:a]+'1'+binary[a:5],2))
           else:
            output[b]=(int('0',2))
           a=a-1
           b=b+1
        if output[key1]==value:
         return 0
        else:
         return 1
    def RequestPacketDecode(stored_binary_data):
        index=0
        global configuration_change,collectionId,Descriptor
        while index < len(stored_binary_data):
            char = stored_binary_data[index]
            length,var_name=SignalingData.decode_Tlv(char)
            if Variable(var_name).name == "Null":
              index+=length
            else:
                if length == TLV_BIG_LEN_IN_BITS:
                  index+=1
                  length=stored_binary_data[index]
                elif length == TLV_EXTRA_BYTE_LEN_IN_BYTES:
                  index+=1
                  length = 0x0100 | stored_binary_data[index] 
       
            if Variable(var_name).name == "Version":
                index+=1
                major = (stored_binary_data[index] & 0x70) >> 5
                minor = (stored_binary_data[index] & 0x1F)
                Values['Version'] = str(major)+"."+str(minor)
            
            elif Variable(var_name).name == "Command":
                index+=1
                Values['Command']=stored_binary_data[index]
                if Values['Command'] == 1:
                  print(Commands.GetCollection)
                elif Values['Command'] == 0:
                  print(Commands.Reserved)
                elif Values['Command'] == 2:
                  print(Commands.ChangePollingFreq)
                else:
                  print(Commands.ChangeRetryGraceCnt)           

            elif Variable(var_name).name == "CollectionId":
                i=index+length
                ascii_list=[]
                BinaryValues['IV']=stored_binary_data[index+1:i+1]
                BinaryValues['CollectionId']=stored_binary_data[index+1:i+1]
                while index<i:
                    index+=1
                    ascii_list.append(stored_binary_data[index])
                collectionId=Values['CollectionId']
                Values['CollectionId']=''.join(chr(key) for key in ascii_list)

            elif Variable(var_name).name == "Nonce":
                i=index+length
                BinaryValues['IV']+=stored_binary_data[index+1:i+1]
                BinaryValues['Nonce']=stored_binary_data[index+1:i+1]
                ascii_list=[]
                while index<i:
                   index+=1
                   ascii_list.append(str(stored_binary_data[index]))
                Values['Nonce']=' '.join(key for key in ascii_list)

            elif Variable(var_name).name == "TimeStamp":
               i=index+length
               ascii_list=[]
               BinaryValues['IV']+=stored_binary_data[index+1:i+1]
               BinaryValues['TimeStamp']=stored_binary_data[index+1:i+1]
               while index<i:
                index+=1
                ascii_list.append(hex(stored_binary_data[index])[2:])
               hex_timestamp = ''.join(map(str, ascii_list))
               current_time = int(hex_timestamp, 16)
               human_readable_time = datetime.datetime.utcfromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')
               Values['TimeStamp']   = human_readable_time 

            elif Variable(var_name).name == "EncryptedBlock":
                BinaryValues['aad']=stored_binary_data[0:index+1]
                i=index+length
                BinaryValues['EncryptedBlock']=stored_binary_data[index+1:i+1]
                BinaryValues['ciphertext']=stored_binary_data[index+1:i+1]
                ascii_list=[]
                while index<i:
                  index+=1
                  ascii_list.append(stored_binary_data[index])
                Values['EncryptedBlock']=' '.join(map(str, ascii_list))
                request_value = [char for char in BinaryValues['aad']]
                d=0

            elif Variable(var_name).name == "EnhanceGcm":
               i=index+length
               ascii_list=[]
               BinaryValues['tag']=stored_binary_data[index+1:i+1]
               BinaryValues['EnhancedGcm']=stored_binary_data[index+1:i+1]
               while index<i:
                index+=1
                ascii_list.append(stored_binary_data[index])
               Values['EnhancedGcm']=' '.join(map(str,ascii_list))
               request_value = [char for char in BinaryValues['tag']]

            elif Variable(var_name).name == "CloudPrinterId":
               i=index+length
               BinaryValues['CloudPrinterId']=stored_binary_data[index+1:i+1]
               ascii_list=[]
               while index<i:
                index+=1
                ascii_list.append(stored_binary_data[index])
               Values['CloudPrinterId']=''.join(chr(key) for key in ascii_list)
 

            elif Variable(var_name).name == "DeviceDescriptor":
              i=index+length
              BinaryValues['Descriptor']=stored_binary_data[index+1:i+1]
              index=i
              Descriptor=Values['Descriptor']
              Values['Descriptor'] = int.from_bytes(BinaryValues['Descriptor'], byteorder='big')

            elif Variable(var_name).name == "AppFlagsAck":
              i=index+length
              Values['AppFlagAsk'] = stored_binary_data[index+1:i+1]
              index=i

            elif Variable(var_name).name == "PrinterStatus":
              i=index+length
              Values['PrinterStatus']=stored_binary_data[index+1:i+1]
              index=i  
            else:
              print("Other")
            index += 1
        return Values

    def response_packet():
        global signaling_ack_by_server,simulator_time
        global reset_count,durationTest,random_ack,duration_ack_bit
        index=0
        decimal_values=[]
        encrypted_values=[]
        enhance_gcm=[]
        #--------------------------------Return Code---------------------------#
        encrypted_values.append((SignalingData.encode_tlv(Variable.ReturnCode,1)))
        encrypted_values.append(int(ReturnCode.Ok))
        #----------------------------ReplyExpiration----------------------------#
        encrypted_values.append(SignalingData.encode_tlv(Variable.ReplyExpiration,1))
        encrypted_values.append(240)
        # #---------------------------App Flag and Collection Content-------------------#
        a=[]
        output=SignalingData.appFlagSet()
        for key ,value in list(output.items()):
            if key<8 and value>0:
                encrypted_values.append(SignalingData.encode_tlv(Variable.AppFlags,1))
                encrypted_values.append(output[key])
                m=SignalingData.setCollectionContent(key,value)
                if m==0:
                  a=[192,0,127]
                  signaling_ack_by_server=signaling_ack_by_server+1
                  reset_count+=1
                  random_ack+=1
                  encrypted_values.append(SignalingData.encode_tlv(Variable.CollectionContent,len(a)))
                  for x in a:
                   encrypted_values.append(x)
                  reset_signal_data.append(reset_signaling_values[key+1])
                  logger1.info(f'Ack from printer to reset bit -> {reset_signaling_values[key+1]}')
                  duration_ack_bit[reset_signaling_values[key+1]]+=1
                else:
                    a=SignalingData.collectionBitmap(int(Values['Descriptor']))
                    if len(a)>5:
                       encrypted_values.append(SignalingData.encode_tlv(Variable.CollectionContent,len(a)))
                       encrypted_values.append(len(a))
                       for x in a:
                        encrypted_values.append(x)
                    else:
                      encrypted_values.append(SignalingData.encode_tlv(Variable.CollectionContent,len(a)))
                      for x in a:
                       encrypted_values.append(x)
            elif key>=8 and value>0:
                encrypted_values.append(SignalingData.encode_tlv(Variable.AppFlags,2))
                encrypted_values.append(0)
                encrypted_values.append(output[key])
                m=SignalingData.setCollectionContent(key,value)
                if m==0:
                  a=[192,0,127]
                  random_ack+=1
                  signaling_ack_by_server=signaling_ack_by_server+1
                  reset_count+=1
                  encrypted_values.append(SignalingData.encode_tlv(Variable.CollectionContent,len(a)))
                  for x in a:
                   encrypted_values.append(x)
                  reset_signal_data.append(reset_signaling_values[key+1])
                  logger1.info(f'Ack from printer to reset bit -> {reset_signaling_values[key+1]}')
                  duration_ack_bit[reset_signaling_values[key+1]]+=1
                else:
                    a=SignalingData.collectionBitmap(int(Values['Descriptor']))
                    if len(a)>5:
                       encrypted_values.append(SignalingData.encode_tlv(Variable.CollectionContent,len(a)))
                       encrypted_values.append(len(a))
                       for x in a:
                        encrypted_values.append(x)
                    else:
                      encrypted_values.append(SignalingData.encode_tlv(Variable.CollectionContent,len(a)))
                      for x in a:
                       encrypted_values.append(x)

        #-----------------------------Command--------------------------#
        encrypted_values.append(SignalingData.encode_tlv(Variable.Command,1))
        encrypted_values.append(int(Commands.ChangeRetryGraceCnt))
        encrypted_values.append(5)
        #-----------------------------Padding--------------------------
        #encrypted_values.append(SignalingData.encode_tlv(Variable.Padding,1))
        #---------------------------------Version------------------------------#
        if Values['Version']=="2.0":
            decimal_values.append(SignalingData.encode_tlv(Variable.Version, 1))
            decimal_values.append(Version.major<<5 | Version.minor)
        else:
            return "Version does not match"
        #--------------------------------Collection ID----------------------------------#
        decimal_values.append(SignalingData.encode_tlv(Variable.CollectionId,len(Values["CollectionId"])))
        decimal_values += [ord(char) for char in Values['CollectionId']]
        enhance_gcm+=[ord(char) for char in Values['CollectionId']]
        #-------------------------------NONCE-----------------------------------------#
        decimal_values.append(SignalingData.encode_tlv(Variable.Nonce,SIG_NONCE_LEN))
        random_bits = secrets.token_bytes(SIG_NONCE_LEN)
        while index<SIG_NONCE_LEN:
            decimal_values.append(random_bits[index])
            enhance_gcm.append(random_bits[index])
            index+=1
        #----------------------------ReplyTimeStamp-----------------------------------#
        decimal_values.append(SignalingData.encode_tlv(Variable.EpochTimeCurrReply,4))
        current_time =int(time.time())
        simulator_time=current_time
        hex_output = hex(current_time)[2:].upper()
        current_time = int(hex_output, 16)
        human_readable_time = datetime.datetime.utcfromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')
        Values['CurrentReplyTime']=human_readable_time
        hex_digits = [hex_output[i:i+2] for i in range(0, len(hex_output), 2)]
        for x in hex_digits:
            decimal_values.append(int(x,16))
            enhance_gcm.append(int(x,16))
        #---------------------------Encrypted Block-------------------------------------#
        decimal_values.append(SignalingData.encode_tlv(Variable.EncryptedBlock,len(encrypted_values)))
        decimal_values.append(len(encrypted_values))
        #------------------------------------------------------------------------
        aad=SignalingData.convert_decimaltohexabinary(decimal_values)
        plaintext=SignalingData.convert_decimaltohexabinary(encrypted_values)
        nonce=SignalingData.convert_decimaltohexabinary(enhance_gcm)
        key=SignalingData.convert_to_bytes(update_config_data["SignatureKey"])
        result=SignalingData.aes_gcm_encrypt(key,nonce,plaintext,aad)
        de=SignalingData.aes_gcm_decrypt(key,nonce,result[0],result[1],aad)
        stored_binary= bytes(aad+result[0]+bytes([SignalingData.encode_tlv(Variable.EnhanceGcm,GCM_TAG_LEN)])+bytes([len(result[1])])+result[1])
        return stored_binary
    
@app.route('/',methods = ['GET'])
def home_page():
    r_data=[]
    s_data=[]
    s_data.extend(set_signal_data)
    if reset_signal_data:
       r_data.extend(reset_signal_data)
       reset_signal_data.clear()
       set_signal_data.clear()
    return render_template('home.html',set_signal_data=s_data,reset_signal_data=r_data)

@app.route('/set_a_signal',methods = ['GET'])
def set_a_signal():
    return render_template('SetSignal.html')

@app.route('/reset_a_signal',methods = ['GET'])
def reset_a_signal():
    zipped_values = zip(set_signaling_values.items(), Signaling_variables.items())
    return render_template('ResetSignal.html',zipped_values=zipped_values)

@app.route('/update_configuration',methods = ['GET'])
def update_configuration():
    global update_config_data
    return render_template('UpdateSignal.html',data=update_config_data)

@app.route('/view_metrics',methods = ['GET'])
def view_metrics():
    global update_config_data
    status_thread = threading.Thread(target=check_printer_status)
    status_thread.start()
    epoch_time=last_request_time
    normal_time = datetime.datetime.utcfromtimestamp(epoch_time)
    m=normal_time.strftime('%Y-%m-%d %H:%M:%S')
    config_thread= threading.Thread(target=get_update_configuration)
    config_thread.start()
    configuration_change=config_thread
    printsimulatorthread=threading.Thread(target=printertime_simulatortime)
    printsimulatorthread.start()
    if signaling_set_by_server!=0:
        signal=((signaling_ack_by_server/signaling_set_by_server)*100)
    else:
        signal=0.0
    

    return render_template('ViewMetrics.html', printer_online=printer_status,printer_last_seen=m,data2=configuration_change,data=old_config_data,data1=update_config_data,signal_set=signaling_set_by_server,signal_ack=signaling_ack_by_server,set_ask=signal,printer_simulator=printer_simulator,polling_delay=(int(update_config_data["PollingDelay"])-int(update_config_data["RandomWindow"])),polling_frequency=int(update_config_data["PollingDelay"]),count=range_count,out=out_count)

@app.route('/duration_test',methods = ['GET'])
def duration_test():
    return render_template('DurationTest.html')

@app.route('/packet_decoder',methods = ['GET'])
def packet_decoder():
   return render_template('PacketDecoder.html')

@app.route('/update_config_data', methods = ['POST'])
def update_config_data1():
    global update_config_data
    if request.method == 'POST':
        global old_config_data
        old_config_data=update_config_data
        ip_address = request.form.get('PrinterID')
        collection_id = request.form.get('CollectionID')
        descriptor = request.form.get('Descriptor')
        signature_key=request.form.get('SignatureKey')
        protocol_switching_policy = request.form.get('ProtocolSwitchingPolicy')
        polling_delay = request.form.get('PollingDelay')
        polling_timeout = request.form.get('PollingTimeout')
        retry_grace_count = request.form.get('RetryGraceCount')
        random_window = request.form.get('RandomWindow')
        printer_status_ratio = request.form.get('PrinterStatusRatio')
        max_gets_between_posts = request.form.get('MaxGetsBetweenPosts')
        url = request.form.get('URL')
        print("IP",ip_address)
        update_config_data = {
            'PrinterID':ip_address,
            'CollectionID': collection_id,
            'Descriptor': descriptor,
            'SignatureKey':signature_key,
            'ProtocolSwitchingPolicy': protocol_switching_policy,
            'PollingDelay': polling_delay,
            'PollingTimeout': polling_timeout,
            'RetryGraceCount': retry_grace_count,
            'RandomWindow': random_window,
            'PrinterStatusRatio': printer_status_ratio,
            'MaxGetsBetweenPosts': max_gets_between_posts,
            'URL': url
        }
        thread3=threading.Thread(target=update_configuration_data, args=(update_config_data,))
        thread3.start()
        
        
        popup_script = """
        <script>
        alert('Configuration form submitted successfully!');
        window.location.href = '/';
        </script>
        """
        return popup_script
    
@app.route('/get_duration', methods=['POST','GET'])
def get_duration():
    global duration_hours
    if request.method == 'POST':
       log_file = 'logfile1.log'
       clear_logs(log_file)
       duration_hours = float(request.form['hours'])
       duration_seconds = duration_hours * 60  # Convert hours to seconds
       status_thread2 = threading.Thread(target=repeat_function, args=(duration_seconds, logger1))
       status_thread2.start()   
       logs=""
       return render_template('logs.html', logs=logs,duration=duration_hours)
    if request.method == 'GET':
       if completeDuration:
          logs = []
          with open('logfile1.log', 'r') as f:
             logs = f.readlines()
       else:
          logs=""
       return render_template('logs.html', logs=logs,duration=duration_hours)
       

@app.route('/set_signaling_data', methods=['POST'])
def set_signaling_data():
    if request.method == 'POST':
        global signaling_set_by_server,set_count,duration_set_bit
        global signaling_ack_by_server
        global set_signaling_values 
        signaling_set_by_server=signaling_set_by_server-signaling_ack_by_server
        signaling_ack_by_server=0
        for name,label in request.form.items():
            set_signaling_values[name]=1
            duration_set_bit[name]+=1
            set_count+=1
            set_signal_data.append(name)
            signaling_set_by_server=signaling_set_by_server+1
        popup_script = """
        <script>
        alert('Set application flag submitted successfully!');
        window.location.href = '/';
        </script>
        """
        return popup_script

@app.route('/reset_signaling_data', methods=['POST'])
def reset_signaling_data():
    if request.method == 'POST':
        global set_signaling_values
        for name,label in request.form.items(): 
            if set_signaling_values[name]==1: 
                set_signaling_values[name]=0 
        popup_script = """
        <script>
        alert('Reset application flag submitted successfully!');
        window.location.href = '/';
        </script>
        """
        return popup_script 
def generate_etag(data):
    data_str = str(data).encode('utf-8')
    return hashlib.sha256(data_str).hexdigest()

@app.route('/server', methods = ['POST','GET'])
def post_json():
    global last_request_time,EtagLast,EtagPresent,last_response_time
    global printer_simulator,range_count,out_count
    last_request_time = time.time()
    x_datetime =int(last_response_time)
    y_datetime =int(last_request_time)
    difference_in_seconds = y_datetime- x_datetime
    if last_response_time:
       if int(update_config_data["RandomWindow"])==0:
           difference_in_seconds+=2
       if difference_in_seconds>=(int(update_config_data["PollingDelay"])-int(update_config_data["RandomWindow"])) and difference_in_seconds<=int(update_config_data["PollingDelay"]):
          range_count+=1
       else:
          out_count+=1
    global stored_binary_data 
    global success_frame
    if request.method == 'POST':
        if request.data:
            stored_binary_data = request.data
            request_value = [char for char in stored_binary_data]
            request_data = ' '.join(map(str, request_value))
            decoder_value=SignalingData.RequestPacketDecode(stored_binary_data)
            key,nonce,ciphertext,tag,aad=SignalingData.gcm_parameter(update_config_data["SignatureKey"])
            encrypted_data= SignalingData.aes_gcm_decrypt(key,nonce,ciphertext,tag,aad)
            encrypted_value=SignalingData.RequestPacketDecode(encrypted_data)
            success_frame=SignalingData.response_packet()
            last_response_time=time.time()
            for appSate, appAsk in zip(list(AppFlagAsk),list(set_signaling_values)):
                if set_signaling_values[appAsk] and AppFlagAsk[appSate]:
                    set_signaling_values[appAsk]=0       
            return success_frame,200
        else:
            return 'No data is received', 400
    elif request.method == 'GET':
        EtagLast=EtagPresent
        EtagPresent = generate_etag(success_frame)
        last_response_time=0
        if EtagLast == EtagPresent:
            return Response(status=304)
        else:
            return success_frame, 200
@app.route('/view', methods=['GET'])
def get_json():
    global stored_binary_data
    if stored_binary_data:
        request_value = [char for char in stored_binary_data]
        request_data = ' '.join(map(str, request_value))
        return render_template('index.html', data=request_data, binary_data=stored_binary_data, data1=Values, set_signaling_values=set_signaling_values)
    else:
        return 'No binary data stored', 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
