import argparse
import sys
import sniffer

parser = argparse.ArgumentParser()
parser.parse_args()
# parser.add_argument('-c', "--no-color",
                    #action = "store_true",
                    #help = "No color coding.")
parser.add_argument('-A', "--all",
                    action = "store_true",
                    help = "Display all packets from all layers.")

parser.add_argument('-t', "--transport",
                    action = "store_true",
                    help = "Only display packets from the transport layer.")

parser.add_argument('-p', "--protocol",
                    default = None,
                    help = "Choose protocols to display.",
                    type=str)
