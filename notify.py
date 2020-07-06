#!/usr/bin/env python3
# PhishDetect
# Copyright (C) 2018-2020  Claudio Guarnieri
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import sys
import time
import argparse
import requests
import traceback
import phishdetect

storage_folder = os.path.join(os.getenv("HOME"), ".config", "phishdetect")
alerts_path = os.path.join(storage_folder, "alerts")
reports_path = os.path.join(storage_folder, "reports")
users_path = os.path.join(storage_folder, "users")

class NothingToReport(Exception):
    pass

def load_data(file_path):
    if not os.path.exists(storage_folder):
        os.makedirs(storage_folder)
        return []

    if not os.path.exists(file_path):
        return []

    print("Parsing {}".format(file_path))

    alerts = []
    with open(file_path, "r") as handle:
        for line in handle:
            line = line.strip()
            if line == "":
                continue

            print("  - adding {}".format(line))
            alerts.append(line)

    return alerts

def add_to_data(file_path, entry):
    with open(file_path, "a") as handle:
        handle.write("{}\n".format(entry))

def send_notification(token, user, msg):
    url = "https://api.pushover.net/1/messages.json"
    data = {
        "token": token,
        "user": user,
        "title": "New PhishDetect Event",
        "message": msg,
    }
    res = requests.post(url, data=data)

def main():
    parser = argparse.ArgumentParser(description="Fetch alerts from the PhishDetect Node")
    parser.add_argument("--node", default=os.getenv("PDNODE", "http://127.0.0.1:7856"), help="URL to the PhishDetect Node (default env PDNODE)")
    parser.add_argument("--key", default=os.getenv("PDKEY", None), help="The API key for your PhishDetect Node user (default env PDKEY)")
    parser.add_argument("--token", default=os.getenv("POTOKEN", None), help="The Pushover token (default env POTOKEN)")
    parser.add_argument("--user", default=os.getenv("POUSER", None), help="The Pushover user (default env POUSER)")
    parser.add_argument("--delay", type=int, default=300, help="Define a delay in seconds between checks")
    args = parser.parse_args()

    if (not args.node or
        not args.key or
        not args.token or
        not args.user):
        parser.print_help()
        sys.exit(-1)

    seen_alerts = load_data(alerts_path)
    seen_reports = load_data(reports_path)
    seen_users = load_data(users_path)

    pd = phishdetect.PhishDetect(host=args.node, api_key=args.key)

    while True:
        print("Checking for new records to report...")

        try:
            alerts = pd.alerts.fetch()
            if not alerts:
                raise NothingToReport
        except NothingToReport:
            pass
        except Exception as e:
            traceback.print_stack()
        else:
            if "error" in alerts:
                print("ERROR: {}".format(alerts["error"]))
            else:
                for alert in alerts:
                    if alert["uuid"] not in seen_alerts:
                        print("Got a new alert with ID {}".format(alert["uuid"]))

                        msg = ""
                        user = alert["user_contact"].strip()
                        if user:
                            msg += "User \"{}\"".format(alert["user_contact"])
                        else:
                            msg += "Unknown user"

                        match = alert["match"].replace("http", "hxxp")
                        match = match.replace(".", "[.]")
                        match = match.replace("@", "[@]")

                        msg += " triggered a {} alert for {}".format(alert["type"], match)

                        send_notification(args.token, args.user, msg)

                        seen_alerts.append(alert["uuid"])
                        add_to_data(alerts_path, alert["uuid"])

        try:
            reports = pd.reports.fetch()
            if not reports:
                raise NothingToReport
        except NothingToReport:
            pass
        except Exception as e:
            traceback.print_stack()
        else:
            if "error" in reports:
                print("ERROR: {}".format(reports["error"]))
            else:
                for report in reports:
                    if report["uuid"] not in seen_reports:
                        print("Got a new report with ID {}".format(report["uuid"]))

                        msg = ""
                        user = report["user_contact"].strip()
                        if user:
                            msg += "User \"{}\"".format(report["user_contact"])
                        else:
                            msg += "Unknown user"

                        msg += " shared a report of type \"{}\" with UUID {}".format(report["type"], report["uuid"])

                        send_notification(args.token, args.user, msg)

                        seen_reports.append(report["uuid"])
                        add_to_data(reports_path, report["uuid"])

        try:
            users = pd.users.get_pending()
            if not users:
                raise NothingToReport
        except NothingToReport:
            pass
        except Exception as e:
            traceback.print_stack()
        else:
            if "error" in users:
                print("ERROR: {}".format(users["error"]))
            else:
                for user in users:
                    if user["key"] not in seen_users:
                        print("Got a new user request for {}".format(user["email"]))

                        msg = "Received a users request for \"{}\" with email {}".format(user["name"], user["email"])
                        send_notification(args.token, args.user, msg)

                        seen_users.append(user["key"])
                        add_to_data(users_path, user["key"])

        time.sleep(args.delay)

if __name__ == "__main__":
    main()
