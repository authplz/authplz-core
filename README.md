# authplz

A simple Authentication and User Management microservice, designed to avoid having to write another authentication and user management service (ever again).

This is intended to provide common user management features (creation/login/logout/password update & reset/token enrolment & validation/email updates/audit logs/oauth token issue/use/revocation) required for a web application (or web application suite) with the minimum possible complexity.

This provides an alternative to hosted solutions such as [StormPath](https://stormpath.com/) and [AuthRocket](https://authrocket.com/) for companies that prefer (or require) locally hosted identity providers. For a well supported locally hosted alternative you may wish to investigate [gluu](https://www.gluu.org), as well as wikipedia's [List of SSO implementations](https://en.wikipedia.org/wiki/List_of_single_sign-on_implementations).

## Status

Early WIP.

[![Build Status](https://travis-ci.com/ryankurte/authplz.svg?token=s4CML2iJ2hd54vvqz5FP&branch=master)](https://travis-ci.com/ryankurte/authplz)

### Tasks

- [X] Refactor to Modules
- [ ] Refactor modules to split API + Controller components (API should only use methods on controller)


## Usage

Frontend components and templates are now in a [ryankurte/authplz-ui](https://github.com/ryankurte/authplz-ui) project. Paths should be set using the `AUTHPLZ_STATICDIR` and `AUTHPLZ_TEMPLATEDIR` environmental flags, or by passing `--static-dir` and `--template-dir` flags on the command line.

For development purposes, it may be convenient to add these variables to your environment (`~/.bashrc` or `~/.bash_profile`).

### Dependencies

- Golang (for building)
- Docker (for building/running docker images and the dev environment)
- Postgres (for user information storage)

### Running

1. Run `make install` to install dependencies
2. Run `./gencert.sh` to generate TLS certificates
3. Run `make build-env` and `make start-env` to build and run dependencies
4. Run `make run` to launch the app

## Features

- [X] Account creation
- [X] Account activation
- [ ] User login - Partial Support, needs redirects from config
- [X] Account locking (and token + password based unlocking)
- [X] User logout
- [X] User password update
- [ ] User Password reset
- [ ] Email notification - Partial, Mailgun implemented, SMTP to go
- [ ] Audit / Event logging
- [X] 2FA token enrolment - partial (Fido, TOTP pending)
- [X] 2FA token validation - Partial, needs integration with password reset
- [ ] 2FA token management
- [ ] OAuth2 delegation
- [ ] ACL grants
- [ ] OAuth2 user management
- [ ] Account linking (google, facebook, github)

## Project Layout

Checkout [DESIGN.md](DESIGN.md) for design notes and API interaction flows.

- [main.go](main.go) contains the launcher for the AuthPlz server
- [api/](api/) contains internal and external API definitions
- [app/](app/) contains the overall application including configuration and wiring (as well as integration tests)
- [appcontext/](appcontext/) contains the base application context (shared across all API modules)
- [controllers/](controllers/) contains controllers that can be shared across API modules
  - [datastore/](datastore/) contains the data storage module and implements the interfaces required by other modules
  - [token/](controllers/token/) contains a token generator and validator
- [modules/](modules/) contains functional modules that can be bound into the system (including interface, controller and API)
  - [core/](modules/core/) contains the core login/logout/action endpoints that further modules are bound into. Checkout this module for information on what components / bindings are available.
  - [user/](modules/user/) contains the user account management module and API
- [templates/](templates/) contains default template files used by components (ie. mailer)
- [test/](test/) contains test helpers (and maybe one day integration tests)

Modules are self-binding and should define interfaces required to function rather than including any (non api or appcontext) other modules.

Each module should define the interfaces required, a controller for interaction / data processing, and an API if required by the module. For an example, checkout [modules/2fa/u2f](modules/2fa/u2f).


------

If you have any questions, comments, or suggestions, feel free to open an issue or a pull request.
