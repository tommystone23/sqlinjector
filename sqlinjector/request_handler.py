
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
from sqlinjector.logger_config import logger
from urllib.parse import urlparse, parse_qs

class RequestHandler:
    def __init__(self):
        self.handlers = {
            "/index"        : Handler("GET", "/index", False, self.index),
            "/data"         : Handler("GET", "/data", True, data),
            "/start-scan"   : Handler("GET", "/start-scan", True, self.start_scan)
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
            logger.error(api_version)
            raise Exception('SQLMap API failed to start')

    def set_root_path(self, root_path : str):
        self.root_path = root_path

    def handle_request(self, request, context):
        tail_url = request.url.replace(self.root_path, '')
        tail_url = tail_url.split('?')[0]
        return self.handlers[tail_url].func(request, context)

    def handle_sse_request(self, request, context):
        tail_url = request.url.replace(self.root_path, '')
        tail_url = tail_url.split('?')[0]
        yield from self.handlers[tail_url].func(request, context)

    def index(self, request, context):
        return module_pb2.Response(
            status=200,
            header=module_pb2.Header(header={"Content-Type": module_pb2.Header.Value(values=["text/html"])}),
            body=self.template.render()
        )

    def start_scan(self, request, context):
        logger.info("starting start_scan()")
        logger.info(f"Using url: {request.url}")
        try:
            url = parse_args(request.url).get('target')
        except Exception as e:
            logger.info(f"failed to get url: {e}")
            return
        task_id = self.api_handler.new_task()
        if(not self.api_handler.start_task(task_id, url=url)):
            logger.error(f"started task with task id: {task_id}")
            return # log and return for now. Return some error html in the future
        while context.is_active():
            response_body = ''
            while self.api_handler.task_status(task_id) != 'terminated':
                time.sleep(5)
            log_json = self.api_handler.task_log(task_id)
            for log in log_json:
                response_body += f"{log.get('message', '')}\n"
                logger.info(log.get('message', '') + '\n')
            response_body += "\n"
            response = module_pb2.Response(
                status=200,
                header=module_pb2.Header(header={
                    "Content-Type": module_pb2.Header.Value(values=["text/event-stream"]),
                    "Cache-Control": module_pb2.Header.Value(values=["no-cache"]),
                    "Connection": module_pb2.Header.Value(values=["keep-alive"])
                }),
                body = response_body
            )
            yield response

            yield module_pb2.Response(
                status=200,
                header=module_pb2.Header(header={
                    "Content-Type": module_pb2.Header.Value(values=["text/event-stream"]),
                }),
                body="STREAM ENDED"
            )
            return

def parse_args(url: str) -> dict:
    parsed_url = urlparse(url)
    query_dict = parse_qs(parsed_url.query)

    # Flatten the values if needed (parse_qs gives a list of values for each key)
    return {k: v[0] if len(v) == 1 else v for k, v in query_dict.items()}

# currently unused
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