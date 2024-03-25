from flask import Flask, request, render_template
import datetime

app = Flask(__name__)

stored_binary_data = b''
def conversion():
    data={}
    decimal_values = list(stored_binary_data)
    version_found = False
    command_found = False
    collection_id_found = False
    nonce_found = False
    timestamp_found = False
    encrypted_block_found = False
    version = ""
    command = ""
    collection_id = ""
    nonce = ""
    timestamp = ""
    encrypted_block = ""
    other = ""
    i = 0
    while i < len(decimal_values):
        if decimal_values[i] == 9 and not version_found:
            version = decimal_values[i+1]
            data["version"]=version
            i=i+1
            version_found = True
        elif decimal_values[i] == 25 and not command_found:
            command = decimal_values[i+1]
            data["command"]=command
            i=i+1
            command_found = True
        elif decimal_values[i] == 20 and not collection_id_found:
            ascii_list = [decimal_values[i+1], decimal_values[i+2], decimal_values[i+3], decimal_values[i+4]]
            collection_id = ''.join(chr(code) for code in ascii_list)
            data["collection_id"]=collection_id
            i=i+4
            collection_id_found = True
        elif decimal_values[i] == 156 and not nonce_found:
            int_array = [decimal_values[i+1], decimal_values[i+2], decimal_values[i+3], decimal_values[i+4]]
            nonce = ' '.join(map(str, int_array))
            data["nonce"]=nonce
            i=i+4
            nonce_found = True
        elif decimal_values[i] == 68 and not timestamp_found:
            int_array = [decimal_values[i+1], decimal_values[i+2], decimal_values[i+3], decimal_values[i+4]]
            hex_timestamp = ''.join(map(str, int_array))
            time = int(hex_timestamp, 16)
            datetime_obj = datetime.datetime.fromtimestamp(time)
            timestamp = datetime_obj.strftime('%Y-%m-%d %H:%M:%S')
            data["timestamp"]=timestamp
            i=i+4
            timestamp_found = True
        elif decimal_values[i] == 134 and not encrypted_block_found:
            encrypted_block = decimal_values[i+1]
            data["encrypted_block"]=encrypted_block
            i=i+1
            encrypted_block_found = True
        else:
            other += str(decimal_values[i]) + " "
        i += 1
    data['other']=other
    return data
@app.route('/',methods=['GET'])
def home_page():
    return render_template('home.html')

@app.route('/set_a_signal',methods=['GET'])
def set_a_signal():
    return render_template('SetSignal.html')

@app.route('/reset_a_signal',methods=['GET'])
def reset_a_signal():
    return render_template('ResetSignal.html')

@app.route('/update_configuration',methods=['GET'])
def update_configuration():
    return render_template('UpdateSignal.html')

@app.route('/view_metrics',methods=['GET'])
def view_metrics():
    return render_template('ViewMetrics.html')

@app.route('/duration_test',methods=['GET'])
def duration_test():
    return render_template('DurationTest.html')

@app.route('/packet_decoder',methods=['GET'])
def packet_decoder():
    return render_template('PacketDecoder.html')

@app.route('/post_json', methods=['POST','GET'])
def post_data():
    global stored_binary_data 
    if request.method == 'POST':
        if request.data:
            stored_binary_data = request.data
            return 'Binary data received successfully',200
        else:
            return 'No data is received', 400
    elif request.method == 'GET':
        if stored_binary_data:
            return 'Get method is success', 200
        else:
            return 'No information available',400

@app.route('/view', methods=['GET'])
def get_json():
    global stored_binary_data
    if stored_binary_data:
        decimal_values = [char for char in stored_binary_data]
        decimal_string = ' '.join(map(str, decimal_values))
        data_size = len(decimal_string)
        data=conversion()
        return render_template('index.html', data=decimal_string, binary_data=stored_binary_data,data_size=data_size,data1=data)
    else:
        return 'No binary data stored', 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
