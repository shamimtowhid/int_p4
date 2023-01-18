BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs

P4C = p4c-bm2-ss
P4C_ARGS += --p4runtime-files $(BUILD_DIR)/$(basename $@).p4.p4info.txt

RUN_SCRIPT = ./utils/run.py

TOPO = ./topology/topology.json

source = $(wildcard *.p4)
compiled_json := $(source:.p4=.json)

DEFAULT_PROG = $(wildcard *.p4)
DEFAULT_JSON = $(BUILD_DIR)/$(DEFAULT_PROG:.p4=.json)

# Define NO_P4 to start BMv2 without a program
run_args += -j $(DEFAULT_JSON)

# Set BMV2_SWITCH_EXE to override the BMv2 target
BMV2_SWITCH_EXE = simple_switch_grpc
run_args += -b $(BMV2_SWITCH_EXE)

all: run

run: build
	sudo python3 $(RUN_SCRIPT) -t $(TOPO) $(run_args)

stop:
	sudo mn -c

build: dirs $(compiled_json)

%.json: %.p4
	$(P4C) --p4v 16 $(P4C_ARGS) -o $(BUILD_DIR)/$@ $<

dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

clean: stop
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)
