import crypto from 'crypto';
import fs     from 'fs';

const words_ = Symbol();

export class Dictionary {
  static loadFromFile(filename) {
    const data = fs.readFileSync(filename, { encoding: 'utf8' });

    const words = data.split('\n').map(line =>
      // Trim spaces and strip out comments.
      line.replace(/^\s*|\s*$/g, '').replace(/^#.*/, '')
    ).filter(line =>
      // Skip blank lines.
      line !== ''
    );

    return new Dictionary(words);
  }

  constructor(words) {
    this[words_] = Array.isArray(words) ? words.slice() : [];
  }

  get wordCount() {
    return this[words_].length;
  }

  wordAt(index) {
    return index < this[words_].length ? this[words_][index] : null;
  }

  randomWord() {
    if (this[words_].length === 0) {
      return null;
    }

    const randomNumber = crypto.randomBytes(2).readUInt16BE();
    const index = Math.floor((randomNumber / 0x10000) * this[words_].length);

    return this[words_][index];
  }
}

// vim: et ts=2 sw=2
