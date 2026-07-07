#!/usr/bin/env node
const { main } = require('../lib/cli');

main(process.argv.slice(2)).then((code) => {
  if (typeof code === 'number') process.exitCode = code;
}).catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exitCode = 1;
});
