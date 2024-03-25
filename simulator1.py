from flask import Flask, request, render_template

app = Flask(__name__)

stored_binary_data = b''

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
            return 'Get method is success', 200
        else:
            return 'No information available',400

@app.route('/view', methods=['GET'])
def get_json():
    global stored_binary_data
    if stored_binary_data:
        decimal_values = [char for char in stored_binary_data]
        decimal_string = ' '.join(map(str, decimal_values))
        data_size = len(stored_binary_data)
        return render_template('index.html', data=decimal_string, binary_data=stored_binary_data, data_size=data_size)
    else:
        return 'No binary data stored', 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
