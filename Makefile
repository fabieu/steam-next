define HELPBODY
Available commands:

	make help       - this thing.

	make init       - install python dependancies
	make test       - run tests and coverage
	make pylint     - code analysis
	make build      - pylint + test

	make pb_fetch   - fetch protobufs from SteamRE
	make pb_compile - compile with protoc
	make pb_clear   - removes *.proto
	make pb_update  - pb_fetch + pb_compile

endef

SHELL := /bin/bash

export HELPBODY
help:
	@echo "$$HELPBODY"

init:
	poetry install --with dev

test:
	pytest --cov=steam

pylint:
	pylint -r n -f colorized steam || true

build:
	poetry build

clean:
	rm -rf dist steam.egg-info steam/*.pyc

webauth_gen:
	rm -f vcr/webauth*
	python3 tests/generete_webauth_vcr.py

pb_fetch:
	wget -nv --show-progress -N -P ./protobufs/ -i protobuf_list.txt || exit 0
	for FN in protobufs/{steammessages_{physicalgoods,webui_friends},gc,test_messages}.proto; do \
		mv "$${FN}" "$${FN}.notouch"; \
	done;
	for FN in protobufs/*.steamclient.proto; do \
		mv "$${FN}" "$${FN/.steamclient.proto/.proto}"; \
	done;
	sed -i '1s/^/syntax = "proto2"\;\n/' protobufs/*.proto
	sed -i 's/cc_generic_services/py_generic_services/' protobufs/*.proto
	sed -i 's/\.steamclient\.proto/.proto/' protobufs/*.proto
	for FN in protobufs/*.proto.notouch; do \
		mv "$${FN}" "$${FN%.notouch}"; \
	done;

pb_compile:
	for filepath in ./protobufs/*.proto; do \
		protoc --python_out ./steam/protobufs/ --proto_path=./protobufs "$$filepath"; \
	done;
	sed -i '/^import sys/! s/^import /import steam.protobufs./' steam/protobufs/*_pb2.py

pb_clear:
	rm -f ./protobufs/*.proto ./steam/protobufs/*_pb2.py

pb_services:
	grep -B 99999 MARK_SERVICE_START steam/core/msg/unified.py > steam/core/msg/unified.py.tmp
	grep '^service' protobufs/*.proto | tr '/.:' ' ' | awk '{ printf("    %-35s '\''steam.protobufs.%s_pb2'\'',\n", "'\''" $$5 "'\'':", $$2) }' >> steam/core/msg/unified.py.tmp
	grep -A 99999 MARK_SERVICE_END steam/core/msg/unified.py >> steam/core/msg/unified.py.tmp
	mv steam/core/msg/unified.py.tmp steam/core/msg/unified.py

pb_gen_enums:
	python3 generate_enums_from_proto.py > steam/enums/proto.py

pb_update: pb_fetch pb_compile pb_services pb_gen_enums
