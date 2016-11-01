# authplz

A simple Authentication and User Management microservice, designed to avoid having to write another authentication or user management service.  
This is intended to provide common user management features (creation/login/logout/password update & reset/token enrolment & validation) required for a web application (or web application suite) with the minum possible complexity.  

This provides an alternative to hosted solutions such as [StormPath](https://stormpath.com/) and [AuthRocket](https://authrocket.com/) for companies that prefer (or require) locally hosted identity providers. For a well supported locally hosted alternative you may wish to investigate [gluu](https://www.gluu.org), as well as wikipedia's [List of SSO implementations](https://en.wikipedia.org/wiki/List_of_single_sign-on_implementations).  

## Status

Early WIP.

[![Build Status](https://travis-ci.com/ryankurte/authplz.svg?token=s4CML2iJ2hd54vvqz5FP&branch=master)](https://travis-ci.com/ryankurte/authplz)

## Usage

### Running
1. Run `make install` to install dependencies
2. Run `./gencert.sh` to generate TLS certificates
3. Run `make run` to launch the app

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


------

If you have any questions, comments, or suggestions, feel free to open an issue or a pull request.
