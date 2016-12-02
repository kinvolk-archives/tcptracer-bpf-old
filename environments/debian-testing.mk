include build.mk

DISTRO=debian-testing

build: build-docker-image build-ebpf-object

linux-version:
	@dpkg -l | perl -n -e'/linux-headers-(.*-amd64) .*/ && print $$1'

linux-headers:
	@dpkg -l | awk '/linux-headers-.*-(common|amd64) .*/{print "/usr/src/"$$2}'
