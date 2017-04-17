# Helpers for AuthPlz development


# Core Functions

default: build

# Install dependencies
install:
	go get -u github.com/go-swagger/go-swagger/cmd/swagger
	go get -u github.com/golang/lint/golint
	go get -u github.com/jteeuwen/go-bindata/...
	go get -u golang.org/x/oauth2
	go get ./...

# Build backend and frontend components
build:
	go build ./cmd/authplz

# Run application
run: build
	./authplz

# Test application
test:
	@go test -p=1 ./lib/...


# Frontend components now in authplz-ui package

# Utilities

lint:
	golint ./lib/...

format:
	gofmt -w -s ./lib/...

validate:
	swagger validate swagger.yml

coverage:
	go test -p=1 -cover ./lib/...
	
checks: format lint coverage

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


.PHONY: start-env stop-env clean-env frontend test
