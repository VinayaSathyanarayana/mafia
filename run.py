#!/usr/bin/python
# -*- coding: utf-8 -*-

from application import app

import gevent
import gevent.monkey
from gevent.pywsgi import WSGIServer

gevent.monkey.patch_all()

PORT = 5000
INTERFACE = '0.0.0.0'

# ------- PRODUCTION CONFIG -------
if __name__ == '__main__':
    try:
        http_server = WSGIServer((INTERFACE, PORT), app)
        if http_server:
            print "Server Started on: http://"+str(INTERFACE)+":"+str(PORT)+"/"

        http_server.serve_forever()


    except KeyboardInterrupt:
        print "\nUser Abort Identified. Good Bye\n"

# ------- DEVELOPMENT CONFIG -------
# if __name__ == "__main__":
#     app.run(host=INTERFACE,port=PORT,debug=True)




