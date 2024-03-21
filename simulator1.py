from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

json_data_with_headers = {}

@app.route('/post_json', methods=['POST'])
def post_json():
    #if not request.is_json:
    #   return jsonify({'error': 'Request must contain JSON data'}), 400
    json_data = request.get_json()
    headers = dict(request.headers)
    global json_data_with_headers
    json_data_with_headers['data'] = json_data
    json_data_with_headers['headers'] = headers

    return jsonify({'message': 'JSON data and headers stored successfully'}), 200

@app.route('/view', methods=['GET'])
def get_json():
    global json_data_with_headers
    return render_template('index.html', data=json_data_with_headers)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
