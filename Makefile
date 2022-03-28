OUTIDR ?= _output
COMPOSE_PROJECT_NAME ?= cloudprober
CONFIG_FILE ?= _dev/cloudprober.cfg

pb-gen:
	@./scripts/pb_gen.sh

gofmt:
#	gofmt -w $$(go list ./...)
	gofmt -w $$(go list ./... | sed -re "s/^github.com\/sun-asterisk-research\/cloudprober\///")

build:
	go build -o _output/cloudprober cmd/cloudprober.go

run:
	go run cmd/cloudprober.go -config_file=$(CONFIG_FILE)

dev:
	docker exec -it $(COMPOSE_PROJECT_NAME)-go-1 go run cmd/cloudprober.go -config_file=$(CONFIG_FILE)

devsh:
	docker exec -it $(COMPOSE_PROJECT_NAME)-go-1 sh

devshroot:
	docker exec -it -u 0:0 $(COMPOSE_PROJECT_NAME)-go-1 sh

devenv:
	COMPOSE_PROJECT_NAME=$(COMPOSE_PROJECT_NAME) UID=$$(id -u) GID=$$(id -g) docker-compose up -d --remove-orphans

devenv-down:
	COMPOSE_PROJECT_NAME=$(COMPOSE_PROJECT_NAME) docker-compose down
