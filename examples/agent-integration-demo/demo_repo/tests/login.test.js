const { bindLogin } = require("../src/login");

let clicked = false;
const button = { addEventListener: (_name, fn) => fn() };
bindLogin(button, () => {
  clicked = true;
});

if (!clicked) {
  throw new Error("login button did not call submit");
}

console.log("ok");
