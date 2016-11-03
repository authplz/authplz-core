# Helpers for AuthPlz development


# Core Functions

# Build backend and frontend components
build: build-go 

# Install dependencies
install: install-go

# Run application
run: run-go

# Test application
test: test-go


# Go Commands

install-go:
	go get -u github.com/go-swagger/go-swagger/cmd/swagger
	go get -u github.com/golang/lint/golint
	go get -u github.com/jteeuwen/go-bindata/...
	go get ./...

build-go:
	go build

run-go: build-go
	./authplz

test-go:
	go test -p=1 ./...


# Frontend components now in authplz-ui package

# Utilities

lint:
	golint ./..

format:
	gofmt -w -s ./..

validate:
	swagger validate swagger.yml

coverage:
	go test -cover
	

# Container control

docker:
	docker build -t ryankurte/authplz .

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


.PHONY: start-env stop-env clean-env frontend
