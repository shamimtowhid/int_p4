# This script will collect packets from all the specified interfaces i.e., s1-eth1, s1-eth2
# Then extract features from IP option header of the packet i.e., egress time, switch_path, q_depth
# Then export those extracted features as JSON data to a specific port using HTTP
# Prometheus will collect these features from the specific port of HTTP
# Prometheus will store the data in the time-series database
# The data from prometheus will be collected as raw data for the visualization tool
# Then Data Wrangling and preprocessing will be conducted 
