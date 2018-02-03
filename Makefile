# Helpers for AuthPlz development


# Core Functions

default: build

dir:
	@mkdir -p build

# Install dependencies
install:
	go get -u github.com/golang/lint/golint
	go get -u github.com/golang/dep/cmd/dep
	go get github.com/golang/mock/gomock
	go get github.com/golang/mock/mockgen

	go get -u github.com/jteeuwen/go-bindata/...
	go get -u golang.org/x/oauth2
	
	dep ensure

# Build backend and frontend components
build:
	go build ./cmd/authplz

# Run application
run: build
	./authplz -c authplz.yml

# Test application
test: mocks
	@go test -p=1 ./lib/...

mocks:
	mockgen -source lib/modules/core/core_interface.go         -destination lib/modules/core/core_mocks.go         -package core
	mockgen -source lib/events/events.go                       -destination lib/events/event_mocks.go              -package events
	mockgen -source lib/controllers/mailer/mailer_interface.go -destination lib/controllers/mailer/mailer_mocks.go -package mailer
	mockgen -source lib/modules/user/user_interface.go         -destination lib/modules/user/user_mocks.go         -package user
	mockgen -source lib/modules/2fa/backup/backup_interface.go -destination lib/modules/2fa/backup/backup_mocks.go -package backup
	mockgen -source lib/modules/oauth/oauth_interface.go       -destination lib/modules/oauth/oauth_mocks.go       -package oauth

cross: dir
	GOOS=linux   GOARCH=amd64 go build  -o build/authplz-linux-amd64 ./cmd/authplz
	GOOS=linux   GOARCH=arm   go build  -o build/authplz-linux-armhf ./cmd/authplz
	GOOS=darwin  GOARCH=amd64 go build  -o build/authplz-linux-armhf ./cmd/authplz
	GOOS=windows GOARCH=amd64 go build  -o build/authplz-windows-amd64 ./cmd/authplz

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
	docker build -t authplz/authplz-core .

# Build containerized development environment
build-env: clean-env
	docker create --name ap-pg -p 5432:5432 postgres
	docker start ap-pg
	sleep 3
	docker run -it --rm --link ap-pg:ap-pg postgres createuser -h ap-pg -U postgres test -drsi
	docker run -it --rm --link ap-pg:ap-pg postgres createdb -h ap-pg -U postgres -O test test
	docker run -it --rm --link ap-pg:ap-pg postgres psql -h ap-pg -U postgres -c "GRANT ALL ON DATABASE test TO test;"
	docker run -it --rm --link ap-pg:ap-pg postgres psql -h ap-pg -U postgres -c "ALTER USER test WITH PASSWORD 'test';"


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


.PHONY: start-env stop-env clean-env frontend test dir
