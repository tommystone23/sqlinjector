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
from sqlinjector.databasecontroller import DatabaseController
import json


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
            "/start-scan": Handler("GET", "/start-scan", False, self.start_scan),
            "/fetch-web-ip": Handler(
                "GET", "/fetch-web-ip", False, self.db_fetch_web_ip
            ),
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

        self.root_path = ""
        self.db_controller = None

    def set_root_path(self, root_path: str):
        self.root_path = root_path

    def set_db_controller(self, db_controller: DatabaseController):
        self.db_controller = db_controller

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

        # wait for scan to complete
        while self.api_handler.task_status(task_id) != "terminated":
            time.sleep(5)

        # collect and parse scan results
        scan_data = self.api_handler.task_data(task_id)
        try:
            response_body, scan_results = self.parse_scan_findings(scan_data)
        except Exception as e:
            logger.info(f"exception in parse scan results: {e}")

        # send password hashes to database
        if scan_results.lpswds:
            proj_id = str(request.header.header["Ptt-Project-Id"].values[0])
            self.db_push_hashes(proj_id, scan_results.lpswds)

        return module_pb2.Response(
            status=200,
            header=module_pb2.Header(
                header={"Content-Type": module_pb2.Header.Value(values=["text/plain"])}
            ),
            body=response_body,
        )

    def parse_scan_findings(self, scan_data: dict) -> tuple[str, ScanResults]:
        scan_results = ScanResults()
        vulnerable = False
        html_ret = self.scan_result_template.render(vulnerable=vulnerable)
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

                value_dict = findings.get("value", {})
                usernames = value_dict.get("`user`", {}).get("values", [])
                passwords = value_dict.get("password", {}).get("values", [])

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

        return html_ret, scan_results

    def db_fetch_web_ip(self, request, context):
        # query db for IP with open port 80
        proj_id = str(request.header.header["Ptt-Project-Id"].values[0])
        open_ports = self.db_controller.fetch_value(
            "github.com/chronotrax/nmap",
            proj_id,
            "open_ports",
        )

        ip = ""
        for entry in open_ports:
            logger.info(entry)
            if entry["port"] == 80:
                ip = entry["ip"]

        json_resp = json.dumps({"ip": ip})
        return module_pb2.Response(
            status=200,
            header=module_pb2.Header(
                header={
                    "Content-Type": module_pb2.Header.Value(values="application/json")
                }
            ),
            body=json_resp,
        )

    def db_push_hashes(self, proj_id: str, pswd_hashes: dict):
        try:
            self.db_controller.push_value(
                "github.com/Penetration-Testing-Toolkit/sqlinjector",
                proj_id,
                "sqli_pswd_hashes",
                json.dumps(pswd_hashes),
            )
        except Exception as e:
            logger.error(f"failed to push value to store: {e}")


def parse_args(url: str) -> dict:
    parsed_url = urlparse(url)
    query_dict = parse_qs(parsed_url.query)

    return {k: v[0] if len(v) == 1 else v for k, v in query_dict.items()}


def filter_args(args: dict) -> dict:
    return {
        key: value for key, value in args.items() if value not in {"Default", "Any", ""}
    }
