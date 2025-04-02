"""
This script runs the a application using a development server.
"""

from os import environ
from app import create_app

if __name__ == '__main__':
    HOST = environ.get('SERVER_HOST', 'localhost')
    try:
        PORT = int(environ.get('SERVER_PORT', '5555'))
    except ValueError:
        PORT = 5555
    create_app().run(HOST, PORT)
