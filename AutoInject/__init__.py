import sys, os, logging
from flask import Flask, render_template, request

def init_app():
    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = ''
    return app

app = init_app()

# Import page views
from AutoInject.bin import views

if __name__ == "__main__":
    
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    print("\t\t\t**** Use CTRL+C then Enter key to exit ****")
    print("\t\t\t\tFlask logging mode off")
    print("\t\t\t**** Access to UI at 127.0.0.1:5000 ****\n")
    app.run(debug=True)