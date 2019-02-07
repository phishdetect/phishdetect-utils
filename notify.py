#!/usr/bin/env python3
# PhishDetect
# Copyright (C) 2018  Claudio Guarnieri
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

config_folder = os.path.join(os.getenv('HOME'), '.config', 'phishdetect')
events_path = os.path.join(config_folder, 'events.txt')

def load_events():
    if not os.path.exists(config_folder):
        os.makedirs(config_folder)
        return []

    if not os.path.exists(events_path):
        return []

    events = []
    with open(events_path, 'r') as handle:
        for line in handle:
            line = line.strip()
            if line == "":
                continue

            events.append(line)

    return events

def get_events(node, key):
    url = '{}/api/events/fetch/'.format(node)
    res = requests.post(url, json={'key': key})

    if res.status_code == 200:
        return res.json()
    else:
        return None

def send_notification(token, user, msg):
    url = 'https://api.pushover.net/1/messages.json'
    data = {
        'token': token,
        'user': user,
        'title': "New PhishDetect Event",
        'message': msg,
    }
    res = requests.post(url, data=data)

def main():
    parser = argparse.ArgumentParser(description="Fetch events from the PhishDetect Node")
    parser.add_argument('--node', default=os.getenv('PDNODE', 'http://127.0.0.1:7856'), help="URL to the PhishDetect Node (default env PDNODE)")
    parser.add_argument('--key', default=os.getenv('PDKEY', None), help="The API key for your PhishDetect Node user (default env PDKEY)")
    parser.add_argument('--token', default=os.getenv('POTOKEN', None), help="The Pushover token (default env POTOKEN)")
    parser.add_argument('--user', default=os.getenv('POUSER', None), help="The Pushover user (default env POUSER)")
    args = parser.parse_args()

    if (not args.node or
        not args.key or
        not args.token or
        not args.user):
        parser.print_help()
        sys.exit(-1)

    seen_events = load_events()

    while True:
        time.sleep(1)

        events = get_events(args.node, args.key)
        if 'error' in events:
            print("ERROR: {}".format(events['error']))
            sys.exit(-1)

        for event in events:
            if event['uuid'] not in seen_events:
                print("Got a new event with ID {}".format(event['uuid']))

                msg = ""
                user = event['user_contact'].strip()
                if user:
                    msg += "User \"{}\"".format(event['user_contact'])
                else:
                    msg += "Unknown user"

                match = event['type'].replace('http', 'hxxp')
                match = match.replace('.', '[.]')
                match = match.replace('@', '[@]')

                msg += " triggered a {} alert for {}".format(event['type'], match)

                send_notification(args.token, args.user, msg)

                seen_events.append(event['uuid'])
                with open(events_path, 'a') as handle:
                    handle.write('{}\n'.format(event['uuid']))

if __name__ == '__main__':
    main()
