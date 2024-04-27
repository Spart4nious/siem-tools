
import re
import argparse

def parse_args():
  parser = argparse.ArgumentParser(description='Extracts raw syslog lines from a pcap')
  parser.add_argument('--scapy-base-directory', dest='SCAPY_MODULE_PATH', default=None, required=False, help='Specify the path where scapy is downloaded if not registered as module already')
  parser.add_argument('--pcap-file', '-f', dest='PCAP_FILE_PATH', required=True, help='The path of the pcap file to be parsed')
  parser.add_argument('--overview', '-O', action='store_true', dest='OVERVIEW_ONLY', required=False, help='Print only the first 10 lines of parsed logs in the stdout' )
  parser.add_argument('--output', '-o', dest='OUTPUT_FILE_PATH', required=False, help='The file path where to write the extracted raw syslog')
  parser.add_argument('--transport', '-t', dest='NETWORK_TRANSPORT', default='UDP', help='The network transport expected in the captured flow')
  parser.add_argument('--port', '-p', dest="NETWORK_PORT", default=514, type=int, help='The network destination port expected in the captured flow')
  args = parser.parse_args()
  return(args)

def is_syslog_packet(p, network_transport, network_port):
  try:
    if p.haslayer(network_transport) and p.dport == network_port:
      syslog_header = re.search('^<\d{1,3}>', p.getlayer('Raw').load.decode(encoding='utf-8'))
      if syslog_header != None:
        return 1
      else:
        return 0
  except Exception as err:
    print("An error occured determining if this is a valid syslog packet")
    print(err)
    return 0

def print_overview(raw_packets, network_transport, network_port):
  for p in raw_packets:
    if is_syslog_packet(p, network_transport, network_port):
      print(p.getlayer('Raw').load.decode(encoding='utf-8'))
    else:
      continue


def __main__():
  args = parse_args()

  if not args.OUTPUT_FILE_PATH and not args.OVERVIEW_ONLY:
    print("You have to specify either the file output where to save data or the overview flag")
    exit(1)

  if args.SCAPY_MODULE_PATH != None:
    import sys
    sys.path.append(args.SCAPY_MODULE_PATH)
  try:
    from scapy.all import rdpcap
  except Exception as load_err:
    print(load_err)
    print("An error occured importing the scapy required module. Please try to provide a local module path or install it in the environment using pip tool")
    exit(1)
  
  
  pcap_path = args.PCAP_FILE_PATH
  
  print("******************************************************************")
  print("Starting analysis and export")
  print("******************************************************************")
  raw_packets = rdpcap(pcap_path)
  if args.OVERVIEW_ONLY:
    counter = 10
    print_overview(raw_packets[:counter], args.NETWORK_TRANSPORT, args.NETWORK_PORT)
  else:
    fo = open(args.OUTPUT_FILE_PATH,'w')
    for p in raw_packets:
      if is_syslog_packet(p, args.NETWORK_TRANSPORT, args.NETWORK_PORT):
        fo.write(f"{p.getlayer('Raw').load.decode(encoding='utf-8')}\n")
      else:
        continue
  print("******************************************************************")
  print("Analysis and export completed")
  print("******************************************************************")

__main__()
  
