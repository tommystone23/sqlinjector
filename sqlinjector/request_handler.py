from dataclasses import dataclass
from jinja2 import Environment, FileSystemLoader, select_autoescape
from proto import module_pb2
import os
import sys
import time
from sqlinjector.api_handler import APIHandler
from sqlinjector.logger_config import logger
from urllib.parse import urlparse, parse_qs
from typing import Callable


@dataclass
class Handler:
    method: str
    path: str
    use_sse: bool
    func: Callable


@dataclass
class ScanResults:
    vulnurl = ""
    vulnparam = ""
    dbtype = ""
    payloads = []
    banner = ""
    cu = ""
    cdb = ""
    hostname = ""
    isdba = ""
    lusers = []
    lprivs = {}
    lroles = {}
    ldbs = []
    lpswds = {}
    ltables = {}


class RequestHandler:
    def __init__(self):
        self.handlers = {
            "/index": Handler("GET", "/index", False, self.index),
            "/start-scan": Handler("GET", "/start-scan", True, self.start_scan),
        }

        if getattr(sys, "frozen", False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(__file__)
        template_path = os.path.join(base_path, "templates")

        env = Environment(
            loader=FileSystemLoader(template_path), autoescape=select_autoescape()
        )
        self.index_template = env.get_template("index.html")
        self.scan_result_template = env.get_template("scan_result_template.html")

        self.api_handler = APIHandler()
        self.api_handler.start_api_server()
        api_version = self.api_handler.version()
        if api_version.startswith("Failed"):
            logger.error(api_version)
            raise Exception("SQLMap API failed to start")

    def set_root_path(self, root_path: str):
        self.root_path = root_path

    def handle_request(self, request, context):
        tail_url = request.url.replace(self.root_path, "")
        tail_url = tail_url.split("?")[0]
        return self.handlers[tail_url].func(request, context)

    def handle_sse_request(self, request, context):
        tail_url = request.url.replace(self.root_path, "")
        tail_url = tail_url.split("?")[0]
        yield from self.handlers[tail_url].func(request, context)

    def index(self, request, context):
        return module_pb2.Response(
            status=200,
            header=module_pb2.Header(
                header={"Content-Type": module_pb2.Header.Value(values=["text/html"])}
            ),
            body=self.index_template.render(),
        )

    def start_scan(self, request, context):
        logger.info(f"starting scan on url {request.url}")
        try:
            args = parse_args(request.url)
            filtered_args = filter_args(args)
            filtered_args["answers"] = "crack=N,dict=N,continue=Y,quit=N"
        except Exception as e:
            logger.error(f"failed to get url: {e}")
            return

        task_id = self.api_handler.new_task()

        if not self.api_handler.start_task(task_id, args=filtered_args):
            logger.error(f"failed to start task with task id: {task_id}")
            return

        while context.is_active():
            response_body = ""
            while self.api_handler.task_status(task_id) != "terminated":
                time.sleep(5)

            scan_data = self.api_handler.task_data(task_id)
            response_body = self.parse_scan_findings(scan_data)

            response = module_pb2.Response(
                status=200,
                header=module_pb2.Header(
                    header={
                        "Content-Type": module_pb2.Header.Value(
                            values=["text/event-stream"]
                        ),
                        "Cache-Control": module_pb2.Header.Value(values=["no-cache"]),
                        "Connection": module_pb2.Header.Value(values=["keep-alive"]),
                    }
                ),
                body=response_body,
            )
            yield response

            yield module_pb2.Response(
                status=200,
                header=module_pb2.Header(
                    header={
                        "Content-Type": module_pb2.Header.Value(
                            values=["text/event-stream"]
                        ),
                    }
                ),
                body="STREAM ENDED",
            )
            return

    def parse_scan_findings(self, scan_data: dict):
        scan_results = ScanResults()
        vulnerable = False
        html_ret = html_ret = self.scan_result_template.render(vulnerable=vulnerable)
        for findings in scan_data:
            vulnerable = True

            # Get vulnerable URL and param
            if findings["type"] == 0:
                scan_results.vulnurl = findings["value"]["url"]
                scan_results.vulnparam = findings["value"]["query"]

            # Get basic scan info
            if findings["type"] == 1:
                dbtype = ""
                if isinstance(findings["value"][0]["dbms"], list):
                    for dbtypes in findings["value"][0]["dbms"]:
                        dbtype = dbtype + dbtypes + ", or "
                    dbtype = dbtype[:-5]
                else:
                    dbtype = findings["value"][0]["dbms"]

                scan_results.dbtype = dbtype

                payloads = []
                for items in findings["value"]:
                    for k in items["data"]:
                        payloads.append(items["data"][k]["payload"])

                scan_results.payloads = payloads

            # Get banner info
            if findings["type"] == 3:
                scan_results.banner = findings["value"]

            # Get Current Users
            elif findings["type"] == 4:
                scan_results.cu = str(findings["value"])

            # Get Current Database
            elif findings["type"] == 5:
                scan_results.cdb = str(findings["value"])

            # Get Hostname
            elif findings["type"] == 6:
                if findings["value"] is not None:
                    scan_results.hostname = str(findings["value"])
                else:
                    scan_results.hostname = "Enumeration failed."

            # Is the user a DBA?
            elif findings["type"] == 7:
                if findings["value"] == True:
                    scan_results.isdba = "Yes"
                else:
                    scan_results.isdba = "No"

            # Get list of users
            elif findings["type"] == 8:
                lusers = []
                for user in findings["value"]:
                    lusers.append(user)

                scan_results.lusers = lusers

            # Get list of passwords
            elif findings["type"] == 9:
                lpswds = {}
                for user in findings["value"]:
                    pswds = []

                    for pswd in findings["value"][user]:
                        pswds.append(pswd)

                    lpswds[user] = pswds

                scan_results.lpswds = lpswds

            # Get list of privileges
            elif findings["type"] == 10:
                lprivs = {}
                for user in findings["value"]:
                    privs = []
                    if findings["value"][user] is not None:
                        for priv in findings["value"][user]:
                            privs.append(priv)
                    else:
                        privs.append("Null")

                    lprivs[user] = privs

                scan_results.lprivs = lprivs

            # Get list of roles
            elif findings["type"] == 11:
                lroles = {}
                for user in findings["value"]:
                    roles = []

                    if findings["value"][user] is not None:
                        for role in findings["value"][user]:
                            roles.append(role)
                    else:
                        roles.append("Null")

                    lroles[user] = roles

                scan_results.lroles = lroles

            # Get list of DBs
            elif findings["type"] == 12:
                ldbs = []
                for db in findings["value"]:
                    ldbs.append(db)

                scan_results.ldbs = ldbs

            # Get list of tables
            elif findings["type"] == 13:
                scan_results.ltables = findings["value"]

            # Get passwords here since normal getPasswordHashes doesn't work
            elif findings["type"] == 17:
                if not isinstance(findings["value"], dict):
                    continue

                usernames = findings["value"]["`user`"]["values"]
                passwords = findings["value"]["password"]["values"]

                scan_results.lpswds = dict(zip(usernames, passwords))

            html_ret = self.scan_result_template.render(
                vulnerable=vulnerable,
                vulnurl=scan_results.vulnurl,
                vulnparam=scan_results.vulnparam,
                dbtype=scan_results.dbtype,
                banner=scan_results.banner,
                cu=scan_results.cu,
                cdb=scan_results.cdb,
                hostname=scan_results.hostname,
                isdba=scan_results.isdba,
                lusers=scan_results.lusers,
                lpswds=scan_results.lpswds,
                lprivs=scan_results.lprivs,
                lroles=scan_results.lroles,
                ldbs=scan_results.ldbs,
                ltables=scan_results.ltables,
            )

        return html_ret


def parse_args(url: str) -> dict:
    parsed_url = urlparse(url)
    query_dict = parse_qs(parsed_url.query)

    return {k: v[0] if len(v) == 1 else v for k, v in query_dict.items()}


def filter_args(args: dict) -> dict:
    return {
        key: value for key, value in args.items() if value not in {"Default", "Any", ""}
    }
