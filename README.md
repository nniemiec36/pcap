# PCAP TCP ANALYSIS

## Libraries
 Program used:
 * Python ver. 3.8.4

 Library used:
 * dpkt [Link - https://pypi.org/project/dpkt/]
 * sys [Link - https://docs.python.org/3.8/library/sys.html]
 * socket [Link - https://docs.python.org/3.8/library/socket.html]
 * prettytable [Link - https://pypi.org/project/prettytable/

## PCAP Programming Task and flow-level information
To use this program:
Execute the program analysis_pcap_tcp.py on the terminal as:
python3 analysis_pcap_tcp.py "pcapfile.pcap"
For example, if you want to analyze connections in "assignment2.pcap":
python3 analysis_pcap_tcp.py assignment2.pcap
it will analyze the connections made in 'assignment2.pcap'

To analyze another .pcap file adjust all lines with a "# sender" or "# receiver" comment.