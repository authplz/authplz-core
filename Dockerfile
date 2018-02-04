FROM golang:latest
MAINTAINER Ryan Kurte <ryankurte@gmail.com>
LABEL Description="Authentication and User Management Microservice"

# Build app
COPY . /go/src/github.com/authplz/authplz-core
WORKDIR /go/src/github.com/authplz/authplz-core
RUN make install
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 make build

# Build UI
FROM node:latest
RUN git clone https://github.com/authplz/authplz-ui.git
WORKDIR /authplz-ui
RUN npm install
RUN npm run build:prod

# Build release image
FROM alpine:latest  
WORKDIR /app/
RUN adduser -D authplz
RUN chown -R authplz:authplz /app
RUN chmod -R o+rx /app

COPY --from=0 /go/src/github.com/authplz/authplz-core/authplz .
COPY --from=0 /go/src/github.com/authplz/authplz-core/authplz.yml config/authplz.yml
COPY --from=0 /go/src/github.com/authplz/authplz-core/templates templates

COPY --from=1 /authplz-ui/build static

ENV HOST=0.0.0.0
ENV PORT=9000
ENV EXTERNAL_ADDRESS=http://authplz.local

#USER authplz
CMD ["/app/authplz -c /app/config/authplz.yml"]  
