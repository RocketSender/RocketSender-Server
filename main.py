from data import db_session
from flask import Flask, make_response, jsonify
from main_api import blueprint
import os.path

db_session.global_init('db\sender.sqlite')
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'status': 'error', 'error': 'Not found'}), 400)


@app.errorhandler(500)
def server_error(error):
    return make_response(jsonify({'status': 'error', 'error': 'Invalid server request'}), 400)


@app.errorhandler(413)
def large_content(error):
    return make_response(jsonify({'status': 'error', 'error': 'File is too large'}), 400)


if __name__ == '__main__':
    app.register_blueprint(blueprint)
    app.run(host='0.0.0.0', port=8080, debug=True, ssl_context='adhoc')
