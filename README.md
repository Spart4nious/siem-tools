# siem-tools
A collection of tools to work around SIEM and data ingestion

extract_raw_syslog_from_pcap.py:
This tool is useful when you need to develop a parser for a non standard datasource, and you don't have a sample data to be parsed to work on. It allows to generate a raw dataset starting from a pcap of a syslog stream, so it is possible to gather the data wothout changes in the running environment (add a further syslog collector to a source) and it is technology independent.
