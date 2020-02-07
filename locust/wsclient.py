#
# ws heavily based on
# https://github.com/websocket-client/websocket-client/blob/master/bin/wsdump.py
#
import iso8601
import json
import os
import re
import ssl
import threading
import websocket

from datetime import datetime
from datetime import timedelta
from dateutil import tz
from urllib.parse import urlparse
from uuid import uuid4


# valid codes for ws read
OPCODE_DATA = (websocket.ABNF.OPCODE_TEXT, websocket.ABNF.OPCODE_BINARY)
#websocket.enableTrace(True)


class SocketClient(object):
    '''hxat websockets client

    connects and reads from ws; does not send anything; ever.
    '''
    def __init__(
            self, locust,
            hxat_session_id,
            hxat_resource_link_id,
            app_url_path='',
            timeout=2,
            verbose=False,
            use_ssl=False,
            ):
        self.locust = locust
        self.hxat_session_id = hxat_session_id
        self.hxat_resource_link_id = hxat_resource_link_id
        self.ws_timeout = timeout
        self.verbose = verbose
        self.session_id = uuid4().hex
        self.protocol = 'wss' if use_ssl else 'ws'

        # get hostname from locust.host
        h = urlparse(locust.host)
        self.hostname = h.netloc

        room_name = '{}--{}--{}'.format(
                re.sub(r'[\W_]', '-', self.locust.hxat['context_id']),
                re.sub(r'[\W_]', '-', self.locust.hxat['collection_id']),
                self.locust.hxat['target_source_id'],
        )

        url_path = os.path.join('/', app_url_path, room_name)
        self.log('-------------- URL_PATH={}'.format(url_path))

        self.url = '{}://{}{}/'.format(
                self.protocol, self.hostname, url_path)

        self.ws = None
        self.thread = None
        self.session_id = None

        events.quitting += self.on_close


    def log(self, msg):
        if self.verbose:
            self.locust.log('[{}] {}'.format(self.session_id, msg))


    def connect(self, as_qs=False, as_header=False, as_cookie=False):
        if self.ws is None:
            self.log('nothing to do: already connected')
            # TODO: have to manage recv thread?
            return

        if as_qs:
            conn_url = '{}?utm_source={}&resource_link_id={}'.format(
                    self.url, self.hxat_session_id,
                    self.hxat_resource_link_id)
        else:
            conn_url = self.url

        self.log('-------------- CONNECT TO URL={}'.format(self.url))
        self.log('-------------- CONNECT TO CONN_URL={}'.format(conn_url))
        self.log('-------------- CONNECT TO HOST={}'.format(self.hostname))

        header = {
            'x_utm_source': self.hxat_session_id,
            'x_lid_source': self.hxat_resource_link_id,
        } if as_header else {}

        cookie = {
            'sessionid': self.hxat_session_id,
            'resourcelinkid': self.hxat_resource_link_id,
        } if as_cookie else {}

        try:
            self.ws = websocket.create_connection(
                    url=conn_url,
                    sslopt={
                        'cert_reqs': ssl.CERT_NONE,  # do not check certs
                        'check_hostname': False,     # do not check hostname
                        },
                    header=header,
                    cookie=cookie,
                    )
        except Exception as e:
            events.request_failure.fire(
                request_type='ws', name='connection',
                response_time=None,
                response_length=0,
                exception=e,
                )
        else:
            events.request_success.fire(
                request_type='ws', name='connection',
                response_time=None,
                response_length=0)

            # if server closes the connection, the thread dies, but
            # if thread dies, it closes the connection?
            self.thread = threading.Thread(
                    target=self.recv,
                    daemon=True
                    )
            self.thread.start()


    def close(self):
        if self.ws is not None:
            self.ws.close()
        else:
            self.log('nothing to do: NOT connected')

    def on_close(self):
        self.close()


    def _recv(self):
        try:
            frame = self.ws.recv_frame()
        except websocket.WebSocketException:
            return websocket.ABNF.OPCODE_CLOSE, None

        if not frame:
            return 0xb, None  # invented code for invalid frame
        elif frame.opcode in OPCODE_DATA:
            return frame.opcode, frame.data
        elif frame.opcode == websocket.ABNF.OPCODE_CLOSE:
            # server closed ws connection
            self.ws.send_close()
            return frame.opcode, None
        elif frame.opcode == websocket.ABNF.OPCODE_PING:
            self.ws.pong(frame.data)
            return frame.opcode, frame.data

        return frame.opcode, frame.data


    def recv(self):
        while True:
            opcode, data = self._recv()

            if opcode == websocket.ABNF.OPCODE_TEXT and isinstance(
                    data, bytes):
                # success
                data = str(data, 'utf-8')
                weba = json.loads(data)
                self.log('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ recv anno_id: {}'.format(weba['message']['id']))
                created = iso8601.parse_date(weba['message']['created'])
                ts_delta = (datetime.now(tz.tzutc()) - \
                        created) / (timedelta(microseconds=1) * 1000)
                response_length = self.calc_response_length(data)
                events.request_success.fire(
                    request_type='ws', name='receive',
                    response_time=ts_delta,
                    response_length=response_length)

            elif opcode == websocket.ABNF.OPCODE_BINARY:
                # failure: don't understand binary
                events.request_failure.fire(
                    request_type='ws', name='receive',
                    response_time=None,
                    response_length=0,
                    exception=websocket.WebSocketException(
                        'Unexpected binary frame'),
                    )

            elif opcode == 0xb:
                # failure: invalid frame
                events.request_failure.fire(
                    request_type='ws', name='receive',
                    response_time=None,
                    response_length=0,
                    exception=websocket.WebSocketException(
                        'Invalid frame'),
                    )

            elif opcode == websocket.ABNF.OPCODE_CLOSE:
                self.log('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ recv CLOSE')
                break  # terminate loop

            elif opcode == websocket.ABNF.OPCODE_PING:
                # ignore ping-pong
                pass

            else:
                # failure: unknown
                events.request_failure.fire(
                    request_type='ws', name='receive',
                    response_time=None,
                    response_length=0,
                    exception=websocket.WebSocketException(
                        '{}| Unknown error for opcode({})'.format(
                            self.session_id, opcode)),
                    )


    def calc_response_length(self, response):
        json_data = json.dumps(response)
        return len(json_data)



