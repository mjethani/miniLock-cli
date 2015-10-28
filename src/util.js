import os       from 'os';
import path     from 'path';
import readline from 'readline';

import nacl     from 'tweetnacl';

export function promisify(thisArg, func) {
  return (...args) => {
    return new Promise((resolve, reject) => {
      func.call(thisArg, ...args, (error, ...values) => {
        if (error) {
          reject(error);
        } else {
          resolve(values);
        }
      });
    });
  };
}

export function hex(data) {
  return new Buffer(data).toString('hex');
}

export function async(func, ...args) {
  process.nextTick(() => {
    func(...args);
  });
}

export function asyncThen(...args) {
  return new Promise(resolve => {
    process.nextTick(() => {
      resolve(args);
    });
  });
}

export function die(...rest) {
  if (rest.length > 0) {
    console.error(...rest);
  }

  process.exit(1);
}

export function logError(error) {
  if (error) {
    console.error(error.toString());
  }
}

export function parseArgs(args, ...rest) {
  // This is another cool function. It parses command line arguments of two
  // kinds: '--long-name[=<value>]' and '-n [<value>]'
  // 
  // If the value is omitted, it's assumed to be a boolean true.
  // 
  // You can pass in default values and a mapping of short names to long names
  // as the first and second arguments respectively.

  const defaultOptions  = typeof rest[0] === 'object' && rest.shift()
      || Object.create(null);
  const shortcuts       = typeof rest[0] === 'object' && rest.shift()
      || Object.create(null);

  let expect = null;
  let stop = false;

  let obj = Object.create(defaultOptions);

  obj = Object.defineProperty(obj, '...', { value: [] });
  obj = Object.defineProperty(obj, '!?',  { value: [] });

  // Preprocessing.
  args = args.reduce((newArgs, arg) => {
    if (!stop) {
      if (arg === '--') {
        stop = true;

      // Split '-xyz' into '-x', '-y', '-z'.
      } else if (arg.length > 2 && arg[0] === '-' && arg[1] !== '-') {
        arg = arg.slice(1).split('').map(v => '-' + v);
      }
    }

    return newArgs.concat(arg);
  },
  []);

  stop = false;

  return args.reduce((obj, arg, index) => {
    const single = !stop && arg[0] === '-' && arg[1] !== '-';

    if (!(single && !(arg = shortcuts[arg]))) {
      if (!stop && arg.slice(0, 2) === '--') {
        if (arg.length > 2) {
          let eq = arg.indexOf('=');

          if (eq === -1) {
            eq = arg.length;
          }

          const name = arg.slice(2, eq);

          if (!single && !Object.prototype.hasOwnProperty.call(defaultOptions,
                name)) {
            obj['!?'].push(arg.slice(0, eq));

            return obj;
          }

          if (single && eq === arg.length - 1) {
            obj[expect = name] = '';

            return obj;
          }

          obj[name] = typeof defaultOptions[name] === 'boolean'
              && eq === arg.length
              || arg.slice(eq + 1);

        } else {
          stop = true;
        }
      } else if (expect) {
        obj[expect] = arg;

      } else if (rest.length > 0) {
        obj[rest.shift()] = arg;

      } else {
        obj['...'].push(arg);
      }

    } else if (single) {
      obj['!?'].push(args[index]);
    }

    expect = null;

    return obj;
  },
  obj);
}

export function prompt(label, quiet) {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
      throw new Error('No TTY');
    }

    if (typeof quiet !== 'boolean') {
      quiet = false;
    }

    if (typeof label === 'string') {
      process.stdout.write(label);
    }

    const rl = readline.createInterface({
      input: process.stdin,
      // The quiet argument is for things like passwords. It turns off standard
      // output so nothing is displayed.
      output: !quiet && process.stdout || null,
      terminal: true
    });

    rl.on('line', line => {
      try {
        rl.close();

        if (quiet) {
          process.stdout.write(os.EOL);
        }

        resolve(line);

      } catch (error) {
        reject(error);
      }
    });
  });
}

export function temporaryFilename() {
  return path.resolve(os.tmpdir(),
      '.mlck-' + hex(nacl.randomBytes(32)) + '.tmp');
}

export function home() {
  return process.env[(process.platform === 'win32') ? 'USERPROFILE' : 'HOME'];
}

// vim: et ts=2 sw=2
