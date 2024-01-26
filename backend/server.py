import os
import datetime
from flask import Flask, request, send_from_directory
app = Flask(__name__, static_folder='../frontend/build')

@app.route('/', defaults={'path':''})
@app.route('/<path:path>')
def index(path):
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')
    # return 'GET request received\n'

@app.route('/handle_msg', methods=['POST'])
def post_test():
    if request.method == 'POST':
        # print(request.json)
        data = request.json
        print(data)
        return {"response": str(request.remote_addr) + " sends: " + str(data['msg']) + '\n'}

@app.route('/data')
def get_time():
    x = datetime.datetime.now() 
    # Returning an api for showing in  reactjs
    return {
        'Name':"geek",
        "Age":"22",
        "Date":x, 
        "programming":"python"
        }

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, use_reloader=True, threaded=True, debug=True)
