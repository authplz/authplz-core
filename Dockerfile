FROM golang:1.7
MAINTAINER Ryan Kurte <ryankurte@gmail.com>
LABEL Description="Authentication and User Management Microservice"

COPY . /go/src/github.com/ryankurte/authplz

WORKDIR /go/src/github.com/ryankurte/authplz

RUN go get -v -d

RUN go install -v
