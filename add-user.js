// Usage: node add-user.js <username> <password> "<Full Name>" [all | "Counter 1;Counter 2"] [email]
const fs = require('fs'), crypto = require('crypto'), path = require('path');
const FILE = path.join(__dirname, 'users.json');
const [, , username, password, name, counters, email] = process.argv;

if (!username || !password) {
  console.log('Usage: node add-user.js <username> <password> "<Full Name>" [all | "Counter 1;Counter 2"] [email]');
  process.exit(1);
}
const hash = pw => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(pw, s, 32).toString('hex'); };

let db = { users: [] };
try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) {}
if (!Array.isArray(db.users)) db = { users: [{ username: db.username, password: db.password, name: 'Admin', email: db.email || '', counters: 'all' }] };

const user = {
  username, password: hash(password), name: name || username, email: email || '',
  counters: (!counters || counters === 'all') ? 'all' : counters.split(';').map(s => s.trim())
};
const i = db.users.findIndex(u => u.username === username);
if (i >= 0) db.users[i] = user; else db.users.push(user);
fs.writeFileSync(FILE, JSON.stringify(db, null, 2));
console.log((i >= 0 ? 'Updated' : 'Added') + ' user: ' + username);