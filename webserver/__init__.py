from flask import Flask, request, Blueprint
from flask_login import LoginManager

app = Flask(__name__)

web = Blueprint('web', __name__)
api = Blueprint('api', __name__, url_prefix='/api')
admin = Blueprint('admin', __name__, url_prefix='/admin')
account = Blueprint('account', __name__, url_prefix='/account')

from .server import init as init_server
from .dataconnector import init as init_db, close_conn
from .login import init as init_login
from .websocket import init as init_socket


def start():
    try:
        init_db()
        init_login()
        init_socket()
        init_server()

        # app.run()
    except Exception as e:
        print(e, 'occured')
    finally:
        close_conn()


if __name__ == 'webserver':
    start()
