# Helpers for AuthPlz development


# Core Functions

build:
	go build

run: build
	./authplz

test:
	go test -p=1 ./...

install:
	go get -u github.com/go-swagger/go-swagger/cmd/swagger
	go get -u github.com/golang/lint/golint
	npm install
	go get ./...


frontend:
	@echo "Building frontend packages"
	./node_modules/webpack/bin/webpack.js --config webpack.config.js --progress --profile --colors

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
