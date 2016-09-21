# Helpers for AuthPlz development

validate:
	swagger validate swagger.yml

bootstrap:
	go get -u github.com/go-swagger/go-swagger/cmd/swagger

install-deps:
	go get ./...

build:
	go build

run: build
	./authplz

# Build containerized development environment
build-env:
	docker create --name ap-pg -p 5432:5432 postgres

# Start development environment
start-env:
	docker start ap-pg

# Stop development environment
stop-env:
	docker stop ap-pg

# Clean up development environment
clean-env: stop-env

	docker rm ap-pg

# Lanch interactive PSQL connected to development db
psql:
	docker run -it --rm --link ap-pg:ap-pg postgres psql -h ap-pg -U postgres	


.PHONY: start-env stop-env clean-env
