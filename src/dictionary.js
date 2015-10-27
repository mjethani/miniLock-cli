import fs from 'fs';

const words_ = Symbol();

export default class Dictionary {
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
}

// vim: et ts=2 sw=2
