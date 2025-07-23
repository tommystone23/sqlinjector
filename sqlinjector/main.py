import grpc
from concurrent import futures
import sys

from grpc_health.v1.health import HealthServicer
from grpc_health.v1.health_pb2 import HealthCheckResponse
from grpc_health.v1 import health_pb2_grpc

from proto import module_pb2
from proto import module_pb2_grpc

from sqlinjector.request_handler import RequestHandler

from sqlinjector.logger_config import logger


class SQLInjectionServicer(module_pb2_grpc.ModuleServicer):
    def __init__(self):
        self.req_handler = RequestHandler()

    def Register(self, request, context):
        # store this here for now until we define a use-case for it
        self.db_fd = "unix://" + request.store_server_address
        response = module_pb2.RegisterResponse(
            id="github.com/Penetration-Testing-Toolkit/sqlinjector",
            name="SQLInjector",
            version="0.3.0",
            category=module_pb2.Category.SCANNER,
        )

        root_path = "/plugin/" + response.id
        self.req_handler.set_root_path(root_path)

        for key, value in self.req_handler.handlers.items():
            route = response.routes.add()
            route.method = value.method
            route.path = value.path
            route.use_sse = value.use_sse

        return response

    def Handle(self, request, context):
        return self.req_handler.handle_request(request, context)

    def HandleSSE(self, request, context):
        yield from self.req_handler.handle_sse_request(request, context)


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    module_pb2_grpc.add_ModuleServicer_to_server(SQLInjectionServicer(), server)

    health = HealthServicer()
    health.set("plugin", HealthCheckResponse.ServingStatus.Value("SERVING"))
    health_pb2_grpc.add_HealthServicer_to_server(health, server)

    # Have gRPC assign us an available port
    address = "127.0.0.1:0"
    port = server.add_insecure_port(address)
    server.start()

    # Add the port gRPC assigned to us
    address = address.rsplit(":", 1)[0] + f":{port}"
    print(f"1|1|tcp|{address}|grpc")
    sys.stdout.flush()

    logger.info("SQLInjector plugin starting")
    server.wait_for_termination()
    logger.info("SQLInjector plugin finished")


if __name__ == "__main__":
    try:
        serve()
    except Exception as e:
        logger.error(f"Call to 'serve()' was unsuccessful: {e}")
