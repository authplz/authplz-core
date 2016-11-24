# authplz

A simple Authentication and User Management microservice, designed to avoid having to write another authentication and user management service (ever again).

This is intended to provide common user management features (creation/login/logout/password update & reset/token enrollment & validation/email updates/audit logs/oauth token issue/use/revocation) required for a web application (or web application suite) with the minimum possible complexity.

This provides an alternative to hosted solutions such as [StormPath](https://stormpath.com/) and [AuthRocket](https://authrocket.com/) for companies that prefer (or require) locally hosted identity providers. For a well supported locally hosted alternative you may wish to investigate [gluu](https://www.gluu.org), as well as wikipedia's [List of SSO implementations](https://en.wikipedia.org/wiki/List_of_single_sign-on_implementations).

## Status

Early WIP.

[![Build Status](https://travis-ci.com/ryankurte/authplz.svg?token=s4CML2iJ2hd54vvqz5FP&branch=master)](https://travis-ci.com/ryankurte/authplz)

## Usage

Frontend components and templates are now in a [ryankurte/authplz-ui](https://github.com/ryankurte/authplz-ui) project. Paths should be set using the `AUTHPLZ_STATICDIR` and `AUTHPLZ_TEMPLATEDIR` environmental flags, or by passing `--static-dir` and `--template-dir` flags on the command line.

For development purposes, it may be convenient to add these variables to your environment (`~/.bashrc` or `~/.bash_profile`).

### Dependencies
- Golang (for building)
- Docker (for building/running docker images)
- Postgres (for user information storage)

### Running
1. Run `make install` to install dependencies
2. Run `./gencert.sh` to generate TLS certificates
3. Run `make build-env` and `make start-env` to build and run dependencies
4. Run `make run` to launch the app

## Features

- [X] Account creation
- [X] Account activation
- [ ] User login - Partial Support, needs redirects
- [X] Account locking (and token + password based unlocking)
- [X] User logout
- [ ] User password update
- [ ] User Password reset
- [ ] Email notification - Partial, Mailgun implemented, SMTP to go
- [ ] Audit / Event logging
- [X] 2FA token enrolment
- [X] 2FA token validation - Partial, needs integration with password reset
- [ ] 2FA token management
- [ ] OAuth2 delegation
- [ ] Account linking (google, facebook, github)

## Project Layout



------

If you have any questions, comments, or suggestions, feel free to open an issue or a pull request.
