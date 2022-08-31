import json
import logging
import os

import yaml
import requests

from os import getenv
from time import sleep
from prometheus_client import start_http_server, REGISTRY
from argparse import ArgumentParser

from prometheus_client.metrics_core import GaugeMetricFamily, CounterMetricFamily


def parse_args():
    args_parser = ArgumentParser()

    args_parser.add_argument(
        "--debug",
        help="Set debug mode. Default: false",
        default=getenv("EXPORTER_DEBUG", False),
        type=bool,
    )
    args_parser.add_argument(
        "--port",
        help="Port to expose exporter. Default: 12110",
        default=getenv("EXPORTER_PORT", 12110),
        type=int,
    )
    args_parser.add_argument(
        "--qbittorrent.addr",
        dest='qbittorrent_addr',
        help="Qbittorrent address",
        default=getenv("QBITTORRENT_ADDR")
    )
    args_parser.add_argument(
        "--qbittorrent.cert",
        dest='qbittorrent_cert',
        help="Qbittorrent certificate,",
        default=getenv("QBITTORRENT_CERT")
    )
    args_parser.add_argument(
        "--qbittorrent.port",
        dest='qbittorrent_port',
        help="Qbittorrent port. Default: 8080",
        default=getenv("QBITTORRENT_PORT", "8080")
    )
    args_parser.add_argument(
        "--qbittorrent.username",
        dest='qbittorrent_username',
        help="Qbittorrent username.",
        default=getenv("QBITTORRENT_USERNAME")
    )
    args_parser.add_argument(
        "--qbittorrent.password",
        dest='qbittorrent_password',
        help="Qbittorrent password.",
        default=getenv("QBITTORRENT_PASSWORD")
    )
    args_parser.add_argument(
        "--qbittorrent.auth",
        dest='qbittorrent_auth',
        help="Qbittorrent authentication file. Default: '/qbittorrent_auth.yml'",
        default=getenv("QBITTORRENT_AUTH_FILE", "/qbittorrent_auth.yml")
    )

    return args_parser.parse_args()


class QbittorrentMetrics:
    def __init__(self, args):
        self.args = args
        self.cookies = {}

        self.session = requests.Session()
        self.session.verify = self.args.qbittorrent_cert

        username = ""
        password = ""
        if os.path.isfile(self.args.qbittorrent_auth):
            with open(self.args.qbittorrent_auth) as auth:
                try:
                    auth = yaml.safe_load(auth)
                    username = auth["username"]
                    password = auth["password"]
                except yaml.YAMLError as exc:
                    logging.error(exc)
        else:
            username = self.args.qbittorrent_username
            password = self.args.qbittorrent_password

        r = self.auth(username, password)
        if r.status_code == 403:
            logging.error("IP address banned due to too many failed login attempts.")
            raise KeyboardInterrupt
        if len(r.cookies) == 0:
            logging.error("Authentication with qbittorrent webui failed.")
            raise KeyboardInterrupt
        logging.info("Authentication with qbittorrent webui successful")
        self.session.cookies = r.cookies

        logging.info("Initialising information")
        r = self.request("sync/maindata", {"rid": 0})
        data = json.loads(r.text)
        self.rid = data["rid"]

        self.global_info = {
            "upload": data["server_state"]["alltime_ul"]
        }

        self.last_global_info = {
            "session_upload": data["server_state"]["up_info_data"]
        }

    def update_metrics(self):
        r = self.request("sync/maindata", {"rid": self.rid})
        data = json.loads(r.text)
        self.rid = data["rid"]

        if "server_state" in data:
            state = data["server_state"]

            if "up_info_data" in state:
                new_upload = state["up_info_data"] - self.last_global_info["session_upload"]
                self.global_info["upload"] += new_upload
                self.last_global_info["session_upload"] = state["up_info_data"]
                logging.debug("Upload amount sense last update: " + str(new_upload))

    def collect(self):
        self.update_metrics()

        yield CounterMetricFamily("qbittorrent_upload_total", "Total data uploaded", value=self.global_info["upload"])

    def auth(self, username, password):
        return self.session.post(
            self.args.qbittorrent_addr + ":" + self.args.qbittorrent_port + "/api/v2/auth/login",
            data={
                "username": username,
                "password": password
            },
        )

    def request(self, url, params):
        return self.session.get(
            self.args.qbittorrent_addr + ":" + self.args.qbittorrent_port + "/api/v2/" + url,
            params=params
        )


def main(args):
    if args.debug:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=loglevel)

    REGISTRY.register(QbittorrentMetrics(args))

    logging.info(f"Qbittorrent exporter exposed on port {args.port}...")
    start_http_server(args.port, registry=REGISTRY)

    while True:
        sleep(1)


if __name__ == '__main__':
    try:
        main(parse_args())
    except KeyboardInterrupt:
        logging.info("Qbittorrent exporter execution finished.")
