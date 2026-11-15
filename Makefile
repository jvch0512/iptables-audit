.PHONY: build test sample

build:
	mkdir -p build && fpc -O2 -Fusrc -FUbuild -FEbuild -obuild/iptables-audit src/main.pas

test: build
	mkdir -p build && fpc -O2 -Fusrc -FUbuild -FEbuild -obuild/tests tests/tests.pas && build/tests

sample: build
	mkdir -p docs site
	build/iptables-audit examples > docs/sample-output.txt; true
	build/iptables-audit examples --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "iptables-audit" "Audits iptables-save rule sets: open default policies, accept-all rules, databases and remote admin ports open to the world. Free Pascal." "Synthetic rule sets."
