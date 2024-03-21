from flask import Flask, request, render_template

app = Flask(__name__)

stored_binary_data = b''

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
        return render_template('index.html', data=stored_binary_data)
    else:
        return 'No binary data stored', 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
