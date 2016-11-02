'use strict';

import React from 'react'
import { render } from 'react-dom'
import { Router, Route, Link, IndexRoute, hashHistory } from 'react-router'
import { BrowserHistory } from 'react-history'

// Create user form component
export class CreateUserForm extends React.Component {
  constructor(props) {
    super(props);
    // Create form state
    this.state = {
      email: '',
      passwordOne: '',
      passwordTwo: '',
      csrf: '',
      successMessage: '',
      errorMessage: ''
    }
    // Bind handlers
    this.handleEmailChange = this.handleEmailChange.bind(this);
    this.getEmailValidation = this.getEmailValidation.bind(this);
    this.handlePasswordOneChange = this.handlePasswordOneChange.bind(this);
    this.handlePasswordTwoChange = this.handlePasswordTwoChange.bind(this);
    this.getPasswordValidation = this.getPasswordValidation.bind(this);
    this.showPasswordHelp = this.showPasswordHelp.bind(this);
    this.handleSubmit = this.handleSubmit.bind(this);
  }

  // Handle form changes
  handleEmailChange(e) {
    this.setState({email: e.target.value});
  }

  getEmailValidation() {
    if(validator.isEmail(this.state.email)) {
      return "success"
    }
    return "error"
  }

  handlePasswordOneChange(e) {
    this.setState({passwordOne: e.target.value});
  }

  handlePasswordTwoChange(e) {
    this.setState({passwordTwo: e.target.value});
  }

  getPasswordValidation() {
    if((this.state.passwordOne === this.state.passwordTwo) && (this.state.passwordOne.length > 0)) {
      return "success"
    }
    return "error"
  }

  showPasswordHelp() {
    return (this.state.passwordOne !== this.state.passwordTwo) 
      && (this.state.passwordOne.length > 0)
      && (this.state.passwordTwo.length > 0)
  }

  // Handle submit events
  handleSubmit(event) {
    if(this.state.passwordOne !== this.state.passwordTwo) {
      console.log("Password mismatch")
      return
    }

    AuthPlz.CreateUser(this.state.email, this.state.passwordOne).then((res) => {
      this.setState({successMessage: res})
    }, (res) => {
      this.setState({errorMessage: res})
    })
  }

  render() {
    return (
      <div>
        <Col md={2} />
        <Col md={8}>
          <Alert bsStyle="success" hidden={!this.state.successMessage}>{this.state.successMessage}</Alert>
          <Alert bsStyle="danger" hidden={!this.state.errorMessage}>{this.state.errorMessage}</Alert>
          <Form horizontal>
            <FormGroup controlId="formHorizontalEmail" validationState={this.getEmailValidation()}>
              <Col componentClass={ControlLabel} md={2}>
                Email
              </Col>
              <Col md={10}>
                <FormControl type="email" placeholder="Email" 
                  value={this.state.email}
                  onChange={this.handleEmailChange}
                />
                <FormControl.Feedback />
              </Col>
            </FormGroup>

            <FormGroup controlId="formHorizontalPassword" validationState={this.getPasswordValidation()}>
              <Col componentClass={ControlLabel} md={2}>
                Password
              </Col>
              <Col md={10}>
                <FormControl type="password" placeholder="Password" 
                  value={this.state.passwordOne}
                  onChange={this.handlePasswordOneChange}
                />
                <FormControl.Feedback />
              </Col>
            </FormGroup>

            <FormGroup controlId="formHorizontalPassword" validationState={this.getPasswordValidation()}>
              <Col componentClass={ControlLabel} md={2}>
                Password
              </Col>
              <Col md={10}>
                <FormControl type="password" placeholder="Password" 
                  value={this.state.passwordTwo}
                  onChange={this.handlePasswordTwoChange}
                />
                <FormControl.Feedback />
                <HelpBlock hidden={!this.showPasswordHelp()}>Password fields must match</HelpBlock>
              </Col>
            </FormGroup>

            <div />

            <Col md={12}>
              <FormGroup>
                  <Button onClick={this.handleSubmit}>
                    Create User
                  </Button>
              </FormGroup>
            </Col>
          </Form>
        </Col>
      </div>
    );
  }
}


