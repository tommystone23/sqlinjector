import sys
import os
import urllib.request
import zipfile
from subprocess import Popen
from subprocess import DEVNULL
import json
import time
from sqlinjector.logger_config import logger


class APIHandler:
    def __init__(self):
        self.port = "9200"
        self.host = "127.0.0.1"
        self.api_path = sys._MEIPASS + "/" + "sqlmap" + "/" + "sqlmapapi.py"
        self.process = None
        self.extract_sqlmap()

    def __del__(self):
        if self.process != None:
            self.process.terminate()

    def extract_sqlmap(self):
        if getattr(sys, "frozen", False):
            cur_dir = sys._MEIPASS
        else:
            cur_dir = os.path.dirname(__file__)
        if not os.path.isfile(os.path.join(cur_dir, "sqlmap.zip")):
            logger.warning("No SQLMap zip file", os.path.join(cur_dir, "sqlmap.zip"))
            logger.info(f"Falling back to default path {self.api_path}")
            return
        try:  # Extract sqlmap
            with zipfile.ZipFile(os.path.join(cur_dir, "sqlmap.zip")) as sqlmapzip:
                sqlmapzip.extractall(cur_dir)

            # Remove sqlmap zip file
            os.remove(os.path.join(cur_dir, "sqlmap.zip"))

            # Set API path
            sqlmap_dir = os.path.join(cur_dir, "sqlmap")
            api_file = os.path.join(sqlmap_dir, "sqlmapapi.py")
            if os.path.isfile(api_file):
                self.api_path = api_file
            else:
                logger.error("Could not find SQLMap API file.")
                raise Exception("Error occurred during sqlmap extraction")
        except:
            logger.error("Failed to extract sqlmap.zip")
            exit(1)

    def start_api_server(self, port: str = None):
        if port == None:
            port = self.port
        args = ["python3", self.api_path, "-s", "-H", self.host, "-p", port]
        try:
            process_handle = Popen(args, shell=False, stdout=DEVNULL)
        except Exception as e:
            logger.error(f"An error occurred while starting API server: {e}")
            exit(1)

        self.process = process_handle

    def request(self, url: str, retries=5, args=None):
        data = None
        full_url = f"http://{self.host}:{self.port}{url}"
        for i in range(retries):
            try:
                if args is not None:
                    body = json.dumps(args).encode("utf-8")
                    req = urllib.request.Request(full_url, data=body, method="POST")
                    req.add_header("Content-Type", "application/json")
                else:
                    req = urllib.request.Request(full_url, method="GET")

                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.load(resp)
                break

            except Exception as e:
                time.sleep(1)
        return data

    def version(self, retries=5):
        data = self.request("/version")
        if data and data["success"]:
            return data["version"]
        return "Failed to get SQLMap API version"

    def new_task(self):
        data = self.request("/task/new")
        if data and data["success"]:
            return data["taskid"]
        return -1

    def start_task(self, taskid: int, args: dict):
        # url_opt = {'url': url}
        data = self.request(f"/scan/{taskid}/start", args=args)
        return data and data["success"]

    def stop_task(self, taskid: int):
        data = self.request(f"/scan/{taskid}/stop")
        return data and data["success"]

    def task_status(self, taskid: int):
        data = self.request(f"/scan/{taskid}/status")
        if data and data["success"]:
            return data["status"]
        return "terminated"

    def task_data(self, taskid: int):
        data = self.request(f"/scan/{taskid}/data")
        if data and data["success"]:
            return data["data"]
        return "No task data"

    def task_log(self, taskid: int):
        data = self.request(f"/scan/{taskid}/log")
        if data and data["success"]:
            return data["log"]
