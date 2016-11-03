FROM golang:1.7
MAINTAINER Ryan Kurte <ryankurte@gmail.com>
LABEL Description="Authentication and User Management Microservice"

COPY . /go/src/github.com/ryankurte/authplz

WORKDIR /go/src/github.com/ryankurte/authplz

# Fetch dependencies
RUN make install

# Build app
RUN make build

# TODO: install UI

# Install app
RUN go install -v
