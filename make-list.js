const fs = require('fs'), path = require('path');
const dir = path.join(__dirname, 'public', 'images');
fs.mkdirSync(dir, { recursive: true });
const files = fs.readdirSync(dir).filter(f => /\.(jpe?g|png|webp)$/i.test(f));
fs.writeFileSync(path.join(dir, 'list.json'), JSON.stringify(files, null, 2));
console.log(files.length + ' images listed in public/images/list.json');