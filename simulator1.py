from flask import Flask, request, render_template

app = Flask(__name__)

stored_binary_data = b''

@app.route('/post_json', methods=['POST'])
def post_json():
    global stored_binary_data  
    if request.data:
        stored_binary_data = request.data
        return 'Binary data uploaded successfully', 200
    else:
        return 'No binary data received', 400

@app.route('/view', methods=['GET'])
def get_json():
    global stored_binary_data
    if stored_binary_data:
        return render_template('index.html', data=stored_binary_data)
    else:
        return 'No binary data stored', 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
