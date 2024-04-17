import json
from flask import Flask, jsonify, redirect, request, render_template, url_for
import datetime
from datetime import datetime
from enum import IntEnum
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import time
app = Flask(__name__)

sample_data = ["Item 1", "Item 2", "Item 3", "Item 4"]
download_data = []
update_config_data = {}
reset_signaling_data = {}
stored_binary_data = b''
ascii=[]
success_frame = b''
error_frame = b''
critical_error_frame = b''
encrypted_data=b''
stored_binary =b''
aad=b''
nonce=b''
plaintext=b''
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

index = 0
collection=0
Values={
'Version':'',
'Command':'',
'CollectionId':'',
'Nonce':'',
'TimeStamp':'',
'EncryptedBlock':'',
'EnhancedGcm':'',
'CloudPrinterId':'',
'Descriptor':'0',
'PrinterStatus':'',
'AppFlagAsk':''
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

set_signaling_values = {
'start_tunnel_1': 0,
'start_tunnel_2': 0,
'start_tunnel_3':0,
'start_tunnel_4':0,
'echo':1,
'rtp_kick':0,
'registration_subscription':0,
'cdm_pubsub_1':0,
'cdm_pubsub_2':0,
'cdm_pubsub_3':0,
'connectivityConfig':0,
'device_configuration':0,
}

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

    def gcm_parameter():
        key=SignalingData.convert_to_bytes("TGF1cmVudCB3cm90")
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
        #key =signature Key,nonce=IV==enhance signature
        #aad=unencrypted section including encrypted block key and value length
        cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag[:12]
        return (ciphertext, tag)
    
    def aes_gcm_decrypt(key, nonce, ciphertext, tag, aad):
        cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag, min_tag_length=12),
        backend=default_backend
        )
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(aad)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    
    def convert_to_bytes(key):
        bytes_data = str.encode(key)
        return bytes_data
    
    def appFlagSet():
        first_eight_string = ''.join(str(set_signaling_values[key]) for key in reversed(list(set_signaling_values)[:8]))
        rest_string = ''.join(str(set_signaling_values[key]) for key in reversed(list(set_signaling_values)[8:]))
        first_eight_int = int(first_eight_string, 2)
        rest_int = int(rest_string, 2)
        first_eight_hex = hex(first_eight_int)
        rest_hex = hex(rest_int)
        return first_eight_hex,rest_hex

    def singleRleHeader(first):
       global ascii
       ascii.append(first)

    def extendedRleHeader(first):
       global ascii
       ascii.append(192)
       ascii.append(0)
       ascii.append(first) 
    
    def collectionBitmap(descriptor):
       last=125
       first=int(descriptor/8)-1
       byte=int(descriptor%8)
       lastvalue=125-int(descriptor/8)-2
       firstBool=True
       middleBool=True
       lastBool=True
       while last>0:
        if descriptor%8==0:
            first-=1
        if firstBool:
            if first>=0 and first<64:
                SignalingData.singleRleHeader(first)
            elif first>=64:
                SignalingData.extendedRleHeader(first)
            last=last-first
            firstBool=False
            middleBool=True
        elif middleBool:
            if descriptor!=0:
                last -=1
                ascii.append(128)
                msb_position = byte
                if byte==0:
                  msb_position=8
                value = 1 << (7 - (msb_position - 1))
                ascii.append(value)
            middleBool=False
            lastBool=True
        elif lastBool:
            if descriptor%8==0:
                lastvalue+=1
            if lastvalue>=0 and lastvalue<64:
                SignalingData.singleRleHeader(lastvalue)
            elif lastvalue>=64:
                SignalingData.extendedRleHeader(lastvalue)
            lastBool=False
            last=0
       return ascii

    def RequestPacketDecode(stored_binary_data):
        index=0
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
                ascii_list.append(stored_binary_data[index])
               hex_timestamp = ''.join(map(str, ascii_list))
               Values['TimeStamp']   = hex_timestamp 

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

            elif Variable(var_name).name == "EnhanceGcm":
               i=index+length
               ascii_list=[]
               BinaryValues['tag']=stored_binary_data[index+1:i+1]
               BinaryValues['EnhancedGcm']=stored_binary_data[index+1:i+1]
               while index<i:
                index+=1
                ascii_list.append(stored_binary_data[index])
               Values['EnhancedGcm']=' '.join(map(str,ascii_list))

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
        index=0
        decimal_values=[]
        encrypted_values=[]
        enhance_gcm=[]
        #--------------------------------Return Code---------------------------#
        encrypted_values.append((SignalingData.encode_tlv(Variable.ReturnCode,1)))
        encrypted_values.append(int(ReturnCode.Ok))
        #----------------------------ReplyExpiration----------------------------#
        encrypted_values.append(SignalingData.encode_tlv(Variable.ReplyExpiration,2))
        encrypted_values.append(22)
        encrypted_values.append(12)
        #-------------------------------App Flag--------------------------#
        x,y=SignalingData.appFlagSet()
        if y=='0x0':
           encrypted_values.append(SignalingData.encode_tlv(Variable.AppFlags,1))
           encrypted_values.append(int(x,16)) 
        else:
            encrypted_values.append(SignalingData.encode_tlv(Variable.AppFlags,2))
            encrypted_values.append(int(x,16))
            encrypted_values.append(int(y,16))
        #---------------------------Collection Content-------------------#
        a=[]
        a=SignalingData.collectionBitmap(int(Values['Descriptor']))
        print(a)
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
        encrypted_values.append(int(Commands.ChangePollingFreq))
        #-----------------------------Padding--------------------------
        #encrypted_values.append(SignalingData.encode_tlv(Variable.Padding,1))
        #---------------------------------Version------------------------------#
        decimal_values.append(SignalingData.encode_tlv(Variable.Version, 1))
        decimal_values.append(Version.major<<5 | Version.minor)
        #--------------------------------Collection ID----------------------------------#
        decimal_values.append(SignalingData.encode_tlv(Variable.CollectionId,len(Values['CollectionId'])))
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
        hex_output = hex(current_time)[2:].upper()
        hex_digits = [hex_output[i:i+2] for i in range(0, len(hex_output), 2)]
        for x in hex_digits:
            decimal_values.append(int(x,16))
            enhance_gcm.append(int(x,16))
        #---------------------------Encrypted Block-------------------------------------#
        decimal_values.append(SignalingData.encode_tlv(Variable.EncryptedBlock,6))
        decimal_values.append(len(encrypted_values))
        #------------------------------------------------------------------------
        aad=SignalingData.convert_decimaltohexabinary(decimal_values)
        plaintext=SignalingData.convert_decimaltohexabinary(encrypted_values)
        nonce=SignalingData.convert_decimaltohexabinary(enhance_gcm)
        key=SignalingData.convert_to_bytes("TGF1cmVudCB3cm90")
        result=SignalingData.aes_gcm_encrypt(key,nonce,plaintext,aad)
        de=SignalingData.aes_gcm_decrypt(key,nonce,result[0],result[1],aad)
        stored_binary= bytes(aad+result[0]+bytes([SignalingData.encode_tlv(Variable.EnhanceGcm,GCM_TAG_LEN)])+bytes([len(result[1])])+result[1])
        return stored_binary
    
@app.route('/',methods = ['GET'])
def home_page():
    return render_template('home.html')

@app.route('/set_a_signal',methods = ['GET'])
def set_a_signal():
    return render_template('SetSignal.html')

@app.route('/reset_a_signal',methods = ['GET'])
def reset_a_signal():
    return render_template('ResetSignal.html')

@app.route('/update_configuration',methods = ['GET'])
def update_configuration():
    return render_template('UpdateSignal.html')

@app.route('/view_metrics',methods = ['GET'])
def view_metrics():
    return render_template('ViewMetrics.html', data=sample_data)

@app.route('/duration_test',methods = ['GET'])
def duration_test():
    return render_template('DurationTest.html')

@app.route('/packet_decoder',methods = ['GET'])
def packet_decoder():
    return render_template('PacketDecoder.html')

@app.route('/get_data')
def get_data():

    return jsonify(sample_data)

@app.route('/update_config_data', methods = ['POST'])
def update_config_data():
    global update_config_data
    if request.method == 'POST':
        collection_id = request.form.get('collection_id')
        descriptor = request.form.get('descriptor')
        protocol_switching_policy = request.form.get('protocol_switching_policy')
        polling_delay = request.form.get('polling_delay')
        polling_timeout = request.form.get('polling_timeout')
        retry_grace_count = request.form.get('retry_grace_count')
        random_window = request.form.get('random_window')
        printer_status_ratio = request.form.get('printer_status_ratio')
        max_gets_between_posts = request.form.get('max_gets_between_posts')
        url = request.form.get('url')
        update_config_data = {
            'Collection ID': collection_id,
            'Descriptor': descriptor,
            'Protocol Switching Policy': protocol_switching_policy,
            'Polling Delay': polling_delay,
            'Polling Timeout': polling_timeout,
            'Retry Grace Count': retry_grace_count,
            'Random Window': random_window,
            'Printer Status Ratio': printer_status_ratio,
            'Max Gets Between Posts': max_gets_between_posts,
            'URL': url
        }
        popup_script = """
        <script>
        alert('Configuration form submitted successfully!');
        window.location.href = '/';
        </script>
        """
        return popup_script
    
@app.route('/set_signaling_data', methods=['POST'])
def set_signaling_data():
    if request.method == 'POST':
        global set_signaling_values
        set_signaling_values = {
            'update_configuration': request.form['update_configuration'],
            'start_tunnel_1': request.form['start_tunnel_1'],
            'start_tunnel_2': request.form['start_tunnel_2'],
            'start_tunnel_3': request.form['start_tunnel_3'],
            'start_tunnel_4': request.form['start_tunnel_4'],
            'metrics_push': request.form['metrics_push'],
            'device_configuration': request.form['device_configuration'],
            'echo': request.form['echo'],
            'rtp_kick': request.form['rtp_kick'],
            'fw_update': request.form['fw_update'],
            'registration_subscription': request.form['registration_subscription'],
            'cdm_pubsub_1': request.form['cdm_pubsub_1'],
            'cdm_pubsub_2': request.form['cdm_pubsub_2'],
            'cdm_pubsub_3': request.form['cdm_pubsub_3'],
            'cdm_pubsub_4': request.form['cdm_pubsub_4'],
            'cdm_ondemand_desires': request.form['cdm_ondemand_desires']
        }

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
        global reset_signaling_data
        reset_signaling_data = {
            'update_configuration': request.form['update_configuration'],
            'start_tunnel_1': request.form['start_tunnel_1'],
            'start_tunnel_2': request.form['start_tunnel_2'],
            'start_tunnel_3': request.form['start_tunnel_3'],
            'start_tunnel_4': request.form['start_tunnel_4'],
            'metrics_push': request.form['metrics_push'],
            'device_configuration': request.form['device_configuration'],
            'echo': request.form['echo'],
            'rtp_kick': request.form['rtp_kick'],
            'fw_update': request.form['fw_update'],
            'registration_subscription': request.form['registration_subscription'],
            'cdm_pubsub_1': request.form['cdm_pubsub_1'],
            'cdm_pubsub_2': request.form['cdm_pubsub_2'],
            'cdm_pubsub_3': request.form['cdm_pubsub_3'],
            'cdm_pubsub_4': request.form['cdm_pubsub_4'],
            'cdm_ondemand_desires': request.form['cdm_ondemand_desires']
        }

        popup_script = """
        <script>
        alert('Reset application flag submitted successfully!');
        window.location.href = '/';
        </script>
        """
        return popup_script 

@app.route('/post_json', methods = ['POST','GET'])
def post_json():
    global stored_binary_data 
    global success_frame
    if request.method == 'POST':
        if request.data:
            stored_binary_data = request.data
            decoder_value=SignalingData.RequestPacketDecode(stored_binary_data)
            key,nonce,ciphertext,tag,aad=SignalingData.gcm_parameter()
            encrypted_data= SignalingData.aes_gcm_decrypt(key,nonce,ciphertext,tag,aad)
            encrypted_value=SignalingData.RequestPacketDecode(encrypted_data)
            success_frame=SignalingData.response_packet()
            return success_frame,200
        else:
            return 'No data is received', 400
    elif request.method == 'GET':
        if stored_binary_data:
            success_frame=SignalingData.response_packet()
            print(success_frame)
            return success_frame, 200
        else:
            return error_frame,400

@app.route('/view', methods=['GET'])
def get_json():
    global stored_binary_data
    if stored_binary_data:
        request_value = [char for char in stored_binary_data]
        request_data = ' '.join(map(str, request_value))
        return render_template('index.html', data=request_data, binary_data=stored_binary_data, data1=Values)
    else:
        return 'No binary data stored', 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
