const { bindLogin } = require('../src/login');

let called = false;
const button = {};
bindLogin(button, () => { called = true; });
button.onclick();
if (!called) throw new Error('login submit was not called');
