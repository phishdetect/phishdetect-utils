#!/usr/bin/env python3
# PhishDetect
# Copyright (C) 2018-2019  Claudio Guarnieri
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
import base64
import json
import phishdetect

storage_folder = os.path.join(os.getenv('HOME'), '.config', 'phishdetect')
raw_path = os.path.join(storage_folder, 'misp_reports')

def load_data(file_path):
    if not os.path.exists(storage_folder):
        os.makedirs(storage_folder)
        return []

    if not os.path.exists(file_path):
        return []

    print("Parsing {}".format(file_path))

    events = []
    with open(file_path, 'r') as handle:
        for line in handle:
            line = line.strip()
            if line == "":
                continue

            print("  - adding {}".format(line))
            events.append(line)

    return events

def send_misp_event(token, url, message, user):
    objects = [
        {
            'name': 'email',
            'meta-category': 'network',
            'description': 'Email object describing an email with meta-information',
            'template_uuid': 'a0c666e0-fc65-4be8-b48f-3423d788b552',
            'template_version': 10,
            'Attribute': [
                {
                'category': 'Payload delivery',
                'type': 'attachment',
                'object_relation': 'eml',
                'value': 'Raw Email',
                'data': base64.b64encode(message.encode("utf-8")).decode("utf-8")
                }
            ],
        },
        {
            'name': 'annotaion',
            'meta-category': 'misc',
            'Attribute': [
                {
                'type': 'text',
                'object_relation': 'text',
                'value': user
                }
            ]
        }
    ]

    data = {
        'Event': {
            'info': 'Suspicious Email Submitter',
            'distribution': 0,
            'threat_level_id': 3,
            'analysis': 1,
            'Object': objects
        }
    }

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': token
    }
    return requests.post(url + '/events', data=json.dumps(data), headers=headers)

def main():
    parser = argparse.ArgumentParser(description="Fetch events from the PhishDetect Node")
    parser.add_argument('--node', default=os.getenv('PDNODE', 'http://127.0.0.1:7856'), help="URL to the PhishDetect Node (default env PDNODE)")
    parser.add_argument('--key', default=os.getenv('PDKEY', None), help="The API key for your PhishDetect Node user (default env PDKEY)")
    parser.add_argument('--misp', default=os.getenv('MISPURL', None), help="URL to the MISP instance (default env MISPURL)")
    parser.add_argument('--token', default=os.getenv('MISPTOKEN', None), help="The MISP api token (default env MISPTOKEN)")
    args = parser.parse_args()

    if (not args.node or
        not args.key or
        not args.misp or
        not args.token):
        parser.print_help()
        sys.exit(-1)

    seen_reports = load_data(raw_path)
    pd = phishdetect.PhishDetect(host=args.node, api_key=args.key)

    limit = 100
    offset = 0

    delay = 0
    print("Syncing email reports from {} to {}".format(args.node, args.misp))
    while True:
        time.sleep(delay)
        delay = 60
        print("Fetching email reports from offset {}".format(offset))
        try:
            reports = pd.reports.fetch(limit=limit, offset=offset, report_type='email')
            if not reports:
                print("Response is empty (nothing to do)")
                continue
        except:
            print("ERROR: Unable to connect to PhishDetect")
            continue

        if 'error' in reports:
            print("ERROR: {}".format(reports['error']))
        else:
            for report in reports:
                offset = offset + 1
                if report['uuid'] not in seen_reports:
                    print("Got a new email report with ID {}".format(report['uuid']))

                    res = send_misp_event(args.token, args.misp, report['content'], report['user_contact'])

                    if res.status_code == 200:
                        seen_reports.append(report['uuid'])
                        with open(raw_path, 'a') as handle:
                            handle.write('{}\n'.format(report['uuid']))
                    else:
                        print(res)



if __name__ == '__main__':
    main()
