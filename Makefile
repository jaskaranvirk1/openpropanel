BINARY   := openpropanel
PKG      := ./cmd/openpropanel
VERSION  ?= 0.1.0
CSS_IN   := css/input.css
CSS_OUT  := internal/web/static/app.css
TAILWIND := npx --yes tailwindcss@3
LDFLAGS  := -s -w -X main.version=$(VERSION)

.PHONY: all css build build-local run tidy fmt vet clean rpm dist install help

all: build

help:
	@echo "Open ProPanel make targets:"
	@echo "  make css          Build Tailwind CSS -> $(CSS_OUT)"
	@echo "  make build        Cross-compile static linux/amd64 binary (for the server)"
	@echo "  make build-local  Build for the current host (development)"
	@echo "  make run          Build + run locally in dev mode on :9443"
	@echo "  make rpm          Build an installable .rpm (needs rpmbuild)"
	@echo "  make install      Install on this AlmaLinux host (needs root)"

css:
	$(TAILWIND) -i $(CSS_IN) -o $(CSS_OUT) --minify

## Cross-compile a fully static binary for the AlmaLinux target. CGO is off, so
## no C toolchain is needed and the result is a single portable file.
build: css
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

build-local: css
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

run: build-local
	./bin/$(BINARY) -listen :9443

tidy:
	go mod tidy

fmt:
	go fmt ./...

vet:
	go vet ./...

## Build an .rpm from the prebuilt linux binary (see packaging/openpropanel.spec).
rpm: build
	@mkdir -p dist/rpm/SOURCES dist/rpm/SPECS
	cp bin/$(BINARY) dist/rpm/SOURCES/openpropanel
	cp packaging/openpropanel.service dist/rpm/SOURCES/
	cp packaging/openpropanel.spec dist/rpm/SPECS/
	rpmbuild --define "_topdir $(CURDIR)/dist/rpm" --define "_version $(VERSION)" -bb dist/rpm/SPECS/openpropanel.spec
	@echo "RPM written under dist/rpm/RPMS/"

## Cross-compile release tarballs for linux amd64+arm64 into dist/ (no CI/GoReleaser
## needed). Each archive holds the single binary + systemd unit + installer.
dist: css
	@rm -rf dist && mkdir -p dist/stage
	@cp packaging/openpropanel.service scripts/get.sh dist/stage/
	@for arch in amd64 arm64; do \
		echo "  building linux/$$arch"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/stage/openpropanel $(PKG); \
		tar -czf dist/openpropanel_linux_$$arch.tar.gz -C dist/stage openpropanel openpropanel.service get.sh; \
	done
	@rm -rf dist/stage
	@cd dist && (sha256sum *.tar.gz 2>/dev/null || shasum -a 256 *.tar.gz) > checksums.txt
	@echo "artifacts:" && ls -1 dist/

## Install on this host (AlmaLinux/RHEL). Requires root for dnf/systemd/firewall.
install: build
	sudo ./packaging/install.sh

clean:
	rm -rf bin dist data
