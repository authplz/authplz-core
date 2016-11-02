'use strict';

import React from 'react'
import { render } from 'react-dom'
import { Router, Route, Link, IndexRoute, hashHistory } from 'react-router'
import { BrowserHistory } from 'react-history'

import { Col, Form, FormGroup, ControlLabel, FormControl, Checkbox, Button, Alert } from 'react-bootstrap';
import { AuthPlz } from '../js/authplz';

// Login form component
class LoginForm extends React.Component {
  constructor(props) {
    super(props);
    // Create form state
    this.state = {
      email: '',
      password: '',
      csrf: ''
    }
    // Bind handlers
    this.handleEmailChange = this.handleEmailChange.bind(this);
    this.handlePasswordChange = this.handlePasswordChange.bind(this);
    this.handleSubmit = this.handleSubmit.bind(this);
  }

  // Handle form changes
  handleEmailChange(e) {
    this.setState({email: e.target.value});
  }

  handlePasswordChange(e) {
    this.setState({password: e.target.value});
  }

  // Handle submit events
  handleSubmit(event) {
    console.log('Text field value is: ' + this.state.email);
  }

  render() {
    return (
      <div>
        <Col md={2} />
        <Col md={8} >
          <Form horizontal>
            <FormGroup controlId="formHorizontalEmail">
              <Col componentClass={ControlLabel} md={2}>
                Email
              </Col>
              <Col md={10}>
                <FormControl type="email" placeholder="Email" 
                  value={this.state.email}
                  onChange={this.handleEmailChange}
                />
              </Col>
            </FormGroup>

            <FormGroup controlId="formHorizontalPassword">
              <Col componentClass={ControlLabel} md={2}>
                Password
              </Col>
              <Col md={10}>
                <FormControl type="password" placeholder="Password" 
                  value={this.state.password}
                  onChange={this.handlePasswordChange}
                />
              </Col>
            </FormGroup>

            <FormGroup>
              <Col mdOffset={2} md={10}>
                <Checkbox>Remember me</Checkbox>
              </Col>
            </FormGroup>

            <FormGroup>
              <Col mdOffset={2} md={10}>
                <Button onClick={this.handleSubmit}>
                  Sign in
                </Button>
              </Col>
            </FormGroup>
          </Form>
        </Col>
      </div>
    );
  }

}

export {LoginForm}
