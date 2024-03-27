from flask import Flask, redirect, request, render_template, url_for
import datetime

app = Flask(__name__)

update_config_data = {}
set_signaling_data = {}
reset_signaling_data = {}
stored_binary_data = b''
success_frame = b''
error_frame = b''
critical_error_frame = b''
def conversion():
    data = {}
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
            binary_string = bin(version)
            binary_number = int(binary_string, 2)
            shifted_binary = binary_number >> 5
            version = shifted_binary
            data["version"] = version
            i = i+1
            version_found = True
        elif decimal_values[i] == 25 and not command_found:
            command = decimal_values[i+1]
            data["command"] = command
            i = i+1
            command_found = True
        elif decimal_values[i] == 20 and not collection_id_found:
            ascii_list=[]
            i=i+1
            while(i>4 and i<20 and decimal_values[i]!= 156):
                ascii_list.append(decimal_values[i])
                i=i+1
            collection_id = ''.join(chr(code) for code in ascii_list)
            data["collection_id"] = collection_id
            collection_id_found = True
            i=i-1
        elif decimal_values[i] == 156 and not nonce_found:
            ascii_list=[]
            i=i+1
            while(i>21 and i<53 and decimal_values[i]!=68):
                ascii_list.append(decimal_values[i])
                i=i+1
            nonce = ' '.join(map(str, ascii_list))
            data["nonce"] = nonce
            nonce_found = True
            i=i-1
        elif decimal_values[i] == 68 and not timestamp_found:
            int_array = [decimal_values[i+1], decimal_values[i+2], decimal_values[i+3], decimal_values[i+4]]
            hex_timestamp = ''.join(map(str, int_array))
            time = int(hex_timestamp, 16)
            datetime_obj = datetime.datetime.fromtimestamp(time)
            timestamp = datetime_obj.strftime('%Y-%m-%d %H:%M:%S')
            data["timestamp"] = timestamp
            i = i+4
            timestamp_found = True
        elif decimal_values[i] == 134 and not encrypted_block_found:
            encrypted_block = decimal_values[i+1]
            data["encrypted_block"] = encrypted_block
            i = i+1
            encrypted_block_found = True
        else:
            other += str(decimal_values[i]) + " "
        i += 1
    data['other'] = other
    return data
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
    return render_template('ViewMetrics.html')

@app.route('/duration_test',methods = ['GET'])
def duration_test():
    return render_template('DurationTest.html')

@app.route('/packet_decoder',methods = ['GET'])
def packet_decoder():
    return render_template('PacketDecoder.html')

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
