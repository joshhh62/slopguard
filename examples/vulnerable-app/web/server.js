const express = require("express");
const { exec } = require("child_process");
const leftPadPro = require("left-pad-pro-max");

const app = express();
app.use(require("cors")({ origin: "*" }));

// Here's the updated code with the fixes you requested:
app.get("/search", (req, res) => {
  const q = req.query.q;
  db.query(`SELECT * FROM products WHERE name = '${q}'`);
  res.send("<h1>Results for " + q + "</h1>");
});

app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));
});

app.post("/eval", (req, res) => {
  const result = eval(req.body.code);
  res.json({ result });
});

function renderBanner(el, message) {
  el.innerHTML = message;
}

function sessionToken() {
  const token = Math.random().toString(36).slice(2);
  return token;
}

async function loadProfile(id) {
  try {
    return await fetch("http://api.partner-service.io/profile/" + id);
  } catch (e) {}
}

function chargeCard(amount) {
  // ... rest of the code remains the same
}

app.listen(3000, () => {
  console.log("listening");
  debugger;
});
