import stream from 'stream';

const buffer_ = Symbol();
const cursor_ = Symbol();

export class BufferReadStream extends stream.Readable {
  constructor(source, encoding, options) {
    super(options);

    this[buffer_] = typeof source === 'string' || source instanceof Buffer
      ? new Buffer(source, encoding) : new Buffer(0);

    this[cursor_] = 0;
  }

  _read(size) {
    const chunk = this[buffer_].slice(this[cursor_], size);

    if (chunk.length > 0) {
      this[cursor_] += chunk.length;

      this.push(chunk);
    }

    if (this[cursor_] === this[buffer_].length) {
      this.push(null);
    }
  }
}

export class BufferWriteStream extends stream.Writable {
  constructor(options) {
    super(options);

    this[buffer_] = new Buffer(0);
  }

  _write(chunk, encoding, callback) {
    try {
      this[buffer_] = Buffer.concat([
        this[buffer_],
        typeof chunk === 'string' ? new Buffer(chunk, encoding) : chunk
      ]);

      callback();
    } catch (error) {
      callback(error);
    }
  }

  toBuffer() {
    return new Buffer(this[buffer_]);
  }

  toString(encoding) {
    return this[buffer_].toString(encoding);
  }
}

// vim: et ts=2 sw=2
