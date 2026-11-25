const solc = require('solc'); const fs = require('fs'); const path = require('path');
const root = path.resolve(process.argv[2] || __dirname);
const sources = {};
for (const f of ['INNERnetSplit.sol', 'test/MockTokens.sol']) sources[f] = { content: fs.readFileSync(path.join(root, f), 'utf8') };
const input = { language: 'Solidity', sources, settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: 'shanghai',
  outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object', 'evm.methodIdentifiers'] } } } };
const out = JSON.parse(solc.compile(JSON.stringify(input)));
const errs = (out.errors || []).filter(e => e.severity === 'error');
for (const e of out.errors || []) console.error(e.formattedMessage);
if (errs.length) process.exit(1);
const art = { compiler: 'solc ' + solc.version(), settings: input.settings, contracts: {} };
for (const [file, cs] of Object.entries(out.contracts)) for (const [name, c] of Object.entries(cs))
  art.contracts[name] = { source: file, abi: c.abi, bytecode: '0x' + c.evm.bytecode.object, methodIdentifiers: c.evm.methodIdentifiers };
fs.writeFileSync(path.join(root, 'build', 'contracts.json'), JSON.stringify(art, null, 1) + '\n');
console.log('compiled', Object.keys(art.contracts).join(', '), art.compiler);
