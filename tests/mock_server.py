#!/usr/bin/env python3

import base64
import json
import os
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib

HOST = "127.0.0.1"
PORT = 8080

class MockServerRequestHandler(BaseHTTPRequestHandler):

    DEVICE_CODE_PATTERN = re.compile(r'/device/code')
    ACCESS_TOKEN_PATTERN = re.compile(r'/oauth/access_token')
    USER_INFO_PATTERN = re.compile(r'/user')
    CLIENT_ID = 'the_client_id'
    CLIENT_SECRET = 'the_client_secret'
    SCOPE = 'user'
    USER_CODE = 'CDEF-GABC'
    DEVICE_CODE = 'the_device_code'
    GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code'
    ACCESS_TOKEN  = 'the_access_token'
    VERIFICATION_URL = 'http://{}:{}/oidc/device'.format(HOST, PORT)

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length'])).decode()
        post_data = urllib.parse.parse_qs(body)
        print("POST: {}".format(self.path))
        print("POST: {}".format(post_data))
        if re.search(self.DEVICE_CODE_PATTERN, self.path):
            if not 'client_id' in post_data:
                print("client_id not found")
                self.send_response(403)
                self.end_headers()
                return
            elif post_data['client_id'] != [self.CLIENT_ID]:
                print("client_id not match {} -> {}".format(post_data['client_id'], self.CLIENT_ID))
                self.send_response(403)
                self.end_headers()
                return
            elif not 'scope' in post_data:
                print("scope not found")
                self.send_response(403)
                self.end_headers()
                return
            elif post_data['scope'] != [self.SCOPE]:
                print("scope not match {} -> {}".format(post_data['scope'], self.SCOPE))
                self.send_response(403)
                self.end_headers()
                return
            response_data = {
                'user_code': self.USER_CODE,
                'verification_uri': self.VERIFICATION_URL,
                'verification_uri_complete': '{}?user_code={}'.format(self.VERIFICATION_URL, self.DEVICE_CODE),
                'device_code': self.DEVICE_CODE,
                'error': None,
                'expires_in': 1800
            }
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode())
        elif re.search(self.ACCESS_TOKEN_PATTERN, self.path):
            auth = self.headers.get('Authorization', '')
            id_secrect = '{}:{}'.format(self.CLIENT_ID, self.CLIENT_SECRET)
            encode = base64.b64encode(id_secrect.encode())
            token = auth.split()[1].encode()
            if not 'Basic' in auth:
                print("auth not contains Basic {}".format(auth))
                self.send_response(403)
                self.end_headers()
                return
            elif token != encode:
                print("token not match {} -> {}".format(token, encode))
                self.send_response(403)
                self.end_headers()
                return   
            elif not 'client_id' in post_data:
                print("client_id not found")
                self.send_response(403)
                self.end_headers()
                return
            elif post_data['client_id'] != [self.CLIENT_ID]:
                print("client_id not match {} -> {}".format(post_data['client_id'], self.CLIENT_ID))
                self.send_response(403)
                self.end_headers()
                return
            elif not 'device_code' in post_data:
                print("device_code not found")
                self.send_response(403)
                self.end_headers()
                return
            elif post_data['device_code'] != [self.DEVICE_CODE]:
                print("device_code not match {} -> {}".format(post_data['device_code'], self.DEVICE_CODE))
                self.send_response(403)
                self.end_headers()
                return
            elif not 'grant_type' in post_data:
                print("grant_type not found")
                self.send_response(403)
                self.end_headers()
                return
            elif post_data['grant_type'] != [self.GRANT_TYPE]:
                print("grant_type not match {} -> {}".format(post_data['grant_type'], self.GRANT_TYPE))
                self.send_response(403)
                self.end_headers()
                return
            response_data = {
                'access_token': self.ACCESS_TOKEN,
                'error': None,
                'expires_in': 3600,
                'scope': self.SCOPE,
                'token_type': 'Bearer'
            }
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode())
        else:
            self.send_response(404)
            self.end_headers()
    def do_GET(self):
        print("GET: {}".format(self.path))
        if re.search(self.USER_INFO_PATTERN, self.path):
            auth = self.headers.get('Authorization', '')
            token = 'Bearer ' + self.ACCESS_TOKEN
            if token in auth:
                response_data = {
                    'sub': 'YzQ4YWIzMzJhZjc5OWFkMzgwNmEwM2M5',
                    'username': os.getlogin(),
                    'name': 'is me'
                }
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode())
            else:
                print("auth not match {} -> {}".format(token, auth))
                self.send_response(403)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    try:
        print("listening on {}:{}".format(HOST, PORT))
        httpd = HTTPServer((HOST, PORT), MockServerRequestHandler)
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
        print()