import fs from 'fs';

const data_ = Symbol();

export default class Profile {
  static loadFromFile(filename) {
    return new Profile(fs.readFileSync(filename, { encoding: 'utf8' }));
  }

  constructor(data) {
    this[data_] = JSON.parse(data);
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
