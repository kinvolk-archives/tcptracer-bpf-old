include defaults.mk

UID=$(shell id -u)
PWD=$(shell pwd)

.DEFAULT_GOAL:=do-nothing
do-nothing:
	@echo No target given, doing nothing by default

%:
	make -f environments/$@.mk build
