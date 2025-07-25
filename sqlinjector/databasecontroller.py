from proto import store_pb2, store_pb2_grpc
import json


class DatabaseController:
    def __init__(self, store_client: store_pb2_grpc.StoreStub):
        self.store_client = store_client

    def fetch_value(self, plugin_id: str, project_id: str, key: str) -> list[dict]:
        resp = self.store_client.Get(
            store_pb2.GetRequest(
                plugin_id=plugin_id,
                user_id="shared",
                project_id=project_id,
                key=key,
            )
        )
        return json.loads(resp.value.decode()) if resp.value else []

    def push_value(self, plugin_id: str, project_id: str, key: str, value: str):
        self.store_client.Set(
            store_pb2.SetRequest(
                plugin_id=plugin_id,
                user_id="shared",
                project_id=project_id,
                key=key,
                value=value.encode(),
            )
        )
