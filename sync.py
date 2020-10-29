#!/usr/bin/env python3
# PhishDetect
# Copyright (C) 2020  Claudio Guarnieri
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
import argparse
import phishdetect
from urllib.parse import urlparse

# TODO: Add support for synchronization from multiple nodes.
#       This would eventually require a configuration file of some kind.

def generate_tags(tags, src_node):
    """Generate the list of tags to use in the synchronization of indicators.
    """
    if not tags:
        # If no tags were specified, we use the domain name of the soruce node
        # as a tag.
        parsed = urlparse(src_node)
        return [parsed.netloc,]

    # If tags were provided we clean them up and use those.
    return [tag.lower().strip() for tag in tags.split(",")]

def main():
    parser = argparse.ArgumentParser(description="Synchronize your PhishDetect Node with another")
    parser.add_argument("--node", default=os.getenv("PDNODE", "http://127.0.0.1:7856"),
                        help="URL to the target PhishDetect Node (default env PDNODE)")
    parser.add_argument("--key", default=os.getenv("PDKEY", None),
                        help="The API key for your PhishDetect Node user (default env PDKEY)")
    parser.add_argument("--source-node", required=True,
                        help="URL to the PhishDetect Node you want to fetch indicators from")
    parser.add_argument("--source-key", default=os.getenv("PDSRCKEY", None),
                        help="API key for the source PhishDetect Node, if needed")
    parser.add_argument("--recent", action="store_true",
                        help="Flag to fetch only indicators from last 24 hours")
    parser.add_argument("--enabled", action="store_true", default=False,
                        help="Flag to submit synced indicators as enabled")
    parser.add_argument("--tags", help="Comma-separated list of tags to add to the synced indicators. " \
                                       "If none is specified, one will be generated from the source node address")
    parser.add_argument("--batch-size", type=int, default=500,
                        help="Size of batches of indicators to add to target node")
    args = parser.parse_args()

    # We create a connection to the source PhishDetect Node.
    src_pd = phishdetect.PhishDetect(host=args.source_node, api_key=args.source_key)

    # We generate the list of tags to use.
    tags = generate_tags(args.tags, args.source_node)

    if args.recent:
        # Obtain only the most recent indicators.
        print("Fetching the list of recent indicators from source node...")
        src_iocs = src_pd.indicators.fetch_recent()
    else:
        # Obtain the list of all "active" indicators from the source node.
        # Should be all added in the last 6 months.
        print("Fetching the full list of active indicators from the source node...")
        src_iocs = src_pd.indicators.fetch()

    # We create a connection to the target PhishDetect Node.
    print("Fetching the current list of indicators from the target node...")
    dst_pd = phishdetect.PhishDetect(host=args.node, api_key=args.key)
    current_iocs = dst_pd.indicators.fetch()

    # We loop through the indicators fetched from the source node.
    for iocs_type, indicators in src_iocs.items():
        # We first we clean the list from the source node by comparing it to
        # the list we got from the target node.
        cleaned_list = []
        for ioc in indicators:
            if ioc not in current_iocs[iocs_type]:
                cleaned_list.append(ioc)

        if len(cleaned_list) == 0:
            print(f"No new indicators of type {iocs_type} to add. Skip.")
            continue

        print(f"From a list of {len(indicators)} of type {iocs_type} " \
              f"submitting a filtered list of {len(cleaned_list)}...")

        # Now we loop through the cleaned list of indicators.
        for i in range(0, len(cleaned_list), args.batch_size):
            batch = cleaned_list[i:i+args.batch_size]
            result = dst_pd.indicators.add(indicators=batch,
                                           tags=tags,
                                           indicators_type=iocs_type.rstrip("s"),
                                           enabled=args.enabled)
            if "error" in result:
                print(f"ERROR: Failed to add indicators to target node: {result['error']}")
            else:
                print(result["msg"])

if __name__ == "__main__":
    main()
