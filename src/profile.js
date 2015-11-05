import fs   from 'fs';
import path from 'path';

const VERSION = '0.1';

const data_ = Symbol();

export class Profile {
  static loadFromFile(filename) {
    return new Profile(fs.readFileSync(filename, { encoding: 'utf8' }));
  }

  static saveToFile(profile, filename) {
    // Create profile directory.
    try {
      fs.mkdirSync(path.dirname(filename));
    } catch (error) {
      if (error.code !== 'EEXIST') {
        throw error;
      }
    }

    fs.writeFileSync(filename, JSON.stringify(profile[data_]));
  }

  constructor(data) {
    if (typeof data !== 'string') {
      data = JSON.stringify(data);
    }

    this[data_] = JSON.parse(data);

    if (this[data_].version === undefined) {
      this[data_].version = VERSION;
    }
  }

  get version() {
    return this[data_].version;
  }

  get email() {
    return this[data_].email;
  }

  get id() {
    return this[data_].id;
  }

  get secret() {
    return this[data_].secret;
  }
}

// vim: et ts=2 sw=2
