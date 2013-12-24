from flask import Flask, request

def make_app():
    app = Flask(__name__)

    @app.route('/')
    def hello():
        stack=request.environ.get('x509_client_stack',None)
        if stack:
            return "Hello "+str(stack[0].get_subject())
        else:
            return "Hello Anonymous"

    return app

if __name__ == '__main__':
    make_app().run()