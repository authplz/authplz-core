'use strict';

const mountNode = 'root'

var HelloMessage = React.createClass({
  render: function () {

    return (
      <div>
      <h1>Hello {this.props.message}!</h1>

      <ReactBootstrap.Button>Default</ReactBootstrap.Button>
      </div>
    )
  }
});

$(document).ready(function () {
    console.log("Rendering React components")

    // Render elements
    ReactDOM.render(<HelloMessage message="World" />, document.getElementById('root'));
})
