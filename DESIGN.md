# Design

Design notes and quesions for AuthEngine/AuthPlz.


## Overview

- All endpoints will return 400 bad request if required parameters or fields in the request body are not issued
- Authentication endpoints will return 200 success/201 partial or 403 unauthorized
- Internal errors will result in a 401 internal error with no (or a generic) error message to avoid leaking internal
- Other endpoints will return JSON formatted API messages


## Flows

### Account Creation

1. post username, email, password to /api/users/create
2. server sends account activation email
3. execute activation link
4. server sends account activated email


### Basic Login

1. post email, password to /api/login
2. server responds with 200 success, 201 partial (2fa) or 403 unauthorized


### Account Unlock

1. post email, password to /api/login
2. server responds with 403 unauthorized, sends unlock email to registered address, caches credentials
3. get /api/flash returns "Account locked"
4. user clicks unlock link to /api/action?token=TOKEN
5. server redirects to login page
6. post email, password to /api/login (unless credentials are already cached)
7. server executes unlock token

Seems like this could be more efficient / remove the need for the second login if the user clicks the unlock link with a partially formed session (valid username and password).


### Password Change 

1. user logs in as above
2. user submits old, new passwords to /api/users/account
3. server validates, responds with 200 success or 400 bad request


### U2F enrolment

1. user logs in as above
2. user submits token name to /api/u2f/register
3. server responds with registration challenge
4. browser executes challenge, posts response
5. server validates registration response
6. server responds with 200 success or 401 error


### U2F Login

1. post email, password to /api/login
2. server responds with 201 partial (2fa) and available factors object ({u2f: true})
3. browser fetches challenge from /api/u2f/authenticate
4. browser executes challenge, posts response
5. server responds with 200 success or 403 unauthorized



## Questions

- How do we manage password resets with/without 2fa?
- How do plugins require further login validation (ie. "this doesn't look right, click token in email to validate")?


