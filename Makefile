.DEFAULT: all
.PHONY: all

all: kubestack

kubestack:
	godep go build kubestack.go

install:
	cp -f kubestack /usr/local/bin/

clean:
	rm -f kubestack
