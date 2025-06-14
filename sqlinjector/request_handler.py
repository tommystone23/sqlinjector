
class Handler:
    def __init__(self, method, path, use_sse, func):
        self.method = method
        self.path = path
        self.use_sse = use_sse
        self.func = func

from jinja2 import Environment, FileSystemLoader, select_autoescape
from proto import module_pb2
import os
import sys
from sqlinjector.api_handler import APIHandler
class RequestHandler:
    def __init__(self):
        self.handlers = {
            "/index"        : Handler("GET", "/index", False, self.index),
            "/data"         : Handler("GET", "/data", True, data),
            "/request-scan" : Handler("POST", "/start-scan", True, start_scan)
        }
        
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(__file__)
        template_path = os.path.join(base_path, "templates")

        env = Environment(
            loader=FileSystemLoader(template_path),
            autoescape=select_autoescape()
        )
        self.template = env.get_template("index.html")

        self.api_handler = APIHandler()
        self.api_handler.start_api_server()
        api_version = self.api_handler.version()
        if(api_version.startswith("Failed")):
            print(api_version)
            raise Exception('SQLMap API failed to start')
        print(f'SQLMap API version: {api_version}')

    def set_root_path(self, root_path : str):
        self.root_path = root_path

    def handle_request(self, request, context):
        tail_url = request.url.replace(self.root_path, '')
        return self.handlers[tail_url].func(request, context)

    def index(self, request, context):
        return module_pb2.Response(
            status=200,
            header=module_pb2.Header(header={"Content-Type": module_pb2.Header.Value(values=["text/html"])}),
            body=self.template.render()
        )

import time
def data(request, context):
    count = 1
    while context.is_active():
        response_body = f"Streaming Tick {count}"
        response = module_pb2.Response(
            status=200,
            header=module_pb2.Header(header={
                "Content-Type": module_pb2.Header.Value(values=["text/event-stream"]),
                "Cache-Control": module_pb2.Header.Value(values=["no-cache"]),
                "Connection": module_pb2.Header.Value(values=["keep-alive"])
            }),
            body=response_body
        )

        yield response
        time.sleep(1)
        count += 1
        if count > 5:
            break

# NOTE: remember to change html JS to use Alpine stuff
import json
def start_scan(request, context):
    while context.is_active():
        response_json = {}
        response = module_pb2.Response(
            status=200,
            header=module_pb2.Header(header={
                "Content-Type": module_pb2.Header.Value(values=["text/event-stream"]),
                "Cache-Control": module_pb2.Header.Value(values=["no-cache"]),
                "Connection": module_pb2.Header.Value(values=["keep-alive"])
            }),
            body=json.dumps(response_json)
        )
        yield response