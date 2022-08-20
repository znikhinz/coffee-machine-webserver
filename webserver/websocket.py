import time

from . import app
from .dataconnector import Coffee, db

from flask import request
from flask_socketio import SocketIO, send

socketio = SocketIO(app, logger=False, engineio_logger=False)


@socketio.on('connect')
def connect(data):
    pass


@socketio.on('message')
def handle_data(data):
    coffee_uuid = data['coffee_uuid']

    coffee = Coffee.query.get(coffee_uuid)

    if coffee:
        state = coffee.status
        if state == 0:
            time.sleep(5)
        elif state == 1:
            time.sleep(10)
        elif state == 2:
            pass

        if state != 2:
            state += 1

        coffee.status = state
        db.session.commit()

        send({'status': state})
    else:
        send({'error_code': 404, 'error': 'record_missing'})


def init():
    pass
