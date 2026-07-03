function bindLogin(button, submit) {
  // BUG: click handler is never bound.
  button.onclick = null;
}

module.exports = { bindLogin };
