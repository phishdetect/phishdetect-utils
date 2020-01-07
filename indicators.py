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
import argparse
import phishdetect

def main():
    parser = argparse.ArgumentParser(description="Send indicators to the PhishDetect Node")
    parser.add_argument("--node", default="http://127.0.0.1:7856", help="URL to the PhishDetect Node")
    parser.add_argument("--key", required=True, help="The API key for your PhishDetect Node user")
    parser.add_argument("--type", required=True, help="The type of indicator (\"domain\" or \"email\")")
    parser.add_argument("--tags", help="Comma separated list of tags to to mark the indicator")
    parser.add_argument("--single", metavar="IOC", help="Send this single indicator to PhishDetect Node")
    parser.add_argument("--file", metavar="FILE", help="Send all indicators contained in this file to PhishDetect Node")
    args = parser.parse_args()

    if (not args.single and not args.file) or (args.single and args.file):
        parser.print_help()
        print("\nERROR: You need to specify either --single or --file")
        sys.exit(-1)

    indicators = []
    if args.file:
        if not os.path.exists(args.file):
            print("ERROR: The file you specified at path {} does not exist.".format(args.file))
            sys.exit(-1)

        with open(args.file, "r") as handle:
            for line in handle:
                line = line.strip()
                if line == "":
                    continue

                if line not in indicators:
                    print("Adding indicator: {}".format(line))
                    indicators.append(line)
    elif args.single:
        ioc = args.single.strip()
        if ioc not in indicators:
            print("Adding indicator: {}".format(ioc))
            indicators.append(ioc)

    if len(indicators) == 0:
        print("ERROR: Somehow there are no indicators to submit")
        sys.exit(-1)

    tags = []
    if args.tags:
        for tag in args.tags.split(","):
            tag = tag.strip()
            if tag == "":
                continue

            if tag not in tags:
                tags.append(tag)

    pd = phishdetect.PhishDetect(host=args.node, api_key=args.key)
    result = pd.indicators.add(indicators=indicators,
        indicators_type=args.type, tags=tags)

    print(result)

if __name__ == "__main__":
    main()
