import json
from flask import Flask, jsonify, redirect, request, render_template, url_for
import datetime
from datetime import datetime
from enum import IntEnum
app = Flask(__name__)

sample_data = ["Item 1", "Item 2", "Item 3", "Item 4"]
download_data = []
update_config_data = {}
set_signaling_data = {}
reset_signaling_data = {}
stored_binary_data = b''
success_frame = b''
error_frame = b''
critical_error_frame = b''
HEADER_MASK = 0xF8
HEADER_LEN_MASK = 0x07
TLV_BIG = 0x06
TLV_EXTRA_BYTE = 0x07
TLV_BIG_LEN_IN_BITS = 0xFE
TLV_EXTRA_BYTE_LEN_IN_BYTES = 0xFD
index = 0
collection=0
Values={
'Version':'',
'Command':'',
'CollectionId':'',
'Nonce':'',
'TimeStamp':'',
'EncryptedBlock':'',
'EncryptedBlockLength':'',
'EnhancedGcm':''
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
class Variable(IntEnum):
    Null = 0
    Version = 1
    CollectionId = 2
    Command = 3
    ReturnCode = 4
    CloudPrinterId = 6
    DeviceDescriptor = 7
    TimeStamp = 8 
    PrinterStatus = 13
    EncryptedBlock = 16
    Padding = 17
    AppFlagsAck = 18
    Nonce = 19
    EnhanceGcm = 20
Commands = {
    0: "Reserved",
    1: "GetCollection",
    2: "ChangePollingFreq",
    3: "ChangeRetryGraceCnt"
}

def find_length(tlv):
    var_name = (tlv & HEADER_MASK) >> 3
    if tlv & HEADER_LEN_MASK == TLV_BIG:
        length = TLV_BIG_LEN_IN_BITS
    elif tlv & HEADER_LEN_MASK == TLV_EXTRA_BYTE:
        length = TLV_EXTRA_BYTE_LEN_IN_BYTES
    else:
        length = tlv & HEADER_LEN_MASK
    return length,var_name

def conversion():
    index=0
    while index < len(stored_binary_data):
        char = stored_binary_data[index]
        length,var_name=find_length(char)
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
                  print(Commands[1])
            elif Values['Command'] == 0:
                  print(Commands[0])
            elif Values['Command'] == 2:
                  print(Commands[2])
            else:
                  print(Commands[3])        

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
            print("AAd",BinaryValues['aad'])
            i=index+length
            BinaryValues['EncryptedBlock']=stored_binary_data[index+1:i+1]
            BinaryValues['ciphertext']=stored_binary_data[index+1:i+1]
            print("CipherText",BinaryValues['ciphertext'])
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
        else:
            print("Other")

        index += 1
    return Values
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
        global set_signaling_data
        set_signaling_data = {
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
    if request.method == 'POST':
        if request.data:
            stored_binary_data = request.data
            return 'Binary data received successfully',200
        else:
            return 'No data is received', 400
    elif request.method == 'GET':
        if stored_binary_data:
            return success_frame, 200
        else:
            return error_frame,400

@app.route('/view', methods=['GET'])
def get_json():
    global stored_binary_data
    if stored_binary_data:
        decimal_values = [char for char in stored_binary_data]
        decimal_string = ' '.join(map(str, decimal_values))
        data=conversion()
        return render_template('index.html', data=decimal_string, binary_data=stored_binary_data, data1=data)
    else:
        return 'No binary data stored', 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
