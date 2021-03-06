import crypto   from 'crypto'
import os       from 'os'
import readline from 'readline'

export function sortBy(array, prop) {
  return array.sort((a, b) => -(a[prop] < b[prop]) || +(a[prop] > b[prop]))
}

export function stringDistance(s, t) {
  const a = new Array(t.length + 1)
  for (let x = 0; x < a.length; x++) {
    a[x] = x
  }

  for (let j = 1; j <= s.length; j++) {
    let p = a[0]++
    for (let k = 1; k <= t.length; k++) {
      const o = a[k]
      if (s[j - 1] === t[k - 1]) {
        a[k] = p
      } else {
        a[k] = Math.min(a[k - 1] + 1, a[k] + 1, p + 1)
      }
      p = o
    }
  }

  return a[t.length]
}

export function findCloseMatches(string, candidateList,
    { distanceThreshold = 1 } = {}) {
  const matches = candidateList.map(candidate => {
    // Split candidate into individual components. e.g. 'output-file' becomes a
    // list containing 'output', 'file', and 'output-file'.
    const candidateWords = candidate.split('-')
    if (candidateWords.length > 1) {
      candidateWords.push(candidate)
    }

    const distance = candidateWords.reduce((distance, word) =>
      // Take the lowest distance.
      Math.min(distance, stringDistance(string, word))
    ,
    Infinity)

    return { candidate, distance }

  }).filter(match => match.distance <= distanceThreshold)

  sortBy(matches, 'distance')

  return matches.map(match => match.candidate)
}

export function arrayCompare(a, b) {
  if (a === b || (a == null && b == null)) {
    return true
  }

  if (a == null || b == null || isNaN(a.length) || isNaN(b.length) ||
      a.length !== b.length) {
    return false
  }

  const n = a.length

  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) {
      return false
    }
  }

  return true
}

export function isBrowser() {
  return typeof window !== 'undefined'
}

export function hex(data) {
  return new Buffer(data).toString('hex')
}

export function async(func, ...args) {
  process.nextTick(() => {
    func(...args)
  })
}

export function die(...rest) {
  if (rest.length > 0) {
    console.error(...rest)
  }

  process.exit(1)
}

export function logError(error) {
  if (error) {
    console.error(error.toString())
  }
}

export function parseArgs(args, ...rest) {
  // This function parses command line arguments of two kinds:
  // '--long-name[=<value>]' and '-n [<value>]'
  //
  // If the value is omitted, it's assumed to be a boolean true.
  //
  // You can pass in default values and a mapping of short names to long names
  // as the first and second arguments respectively.

  const defaultOptions  = typeof rest[0] === 'object' && rest.shift() ||
    Object.create(null)
  const shortcuts       = typeof rest[0] === 'object' && rest.shift() ||
    Object.create(null)

  let expect = null
  let stop = false

  let obj = Object.create(defaultOptions)

  obj = Object.defineProperty(obj, '...', { value: [] })
  obj = Object.defineProperty(obj, '!?',  { value: [] })

  // Preprocessing.
  args = args.reduce((newArgs, arg) => {
    if (!stop) {
      if (arg === '--') {
        stop = true

      // Split '-xyz' into '-x', '-y', '-z'.
      } else if (arg.length > 2 && arg[0] === '-' && arg[1] !== '-') {
        arg = arg.slice(1).split('').map(v => '-' + v)
      }
    }

    return newArgs.concat(arg)
  },
  [])

  stop = false

  return args.reduce((obj, arg, index) => {
    const single = !stop && arg[0] === '-' && arg[1] !== '-'

    if (!(single && !(arg = shortcuts[arg]))) {
      if (!stop && arg.slice(0, 2) === '--') {
        if (arg.length > 2) {
          let eq = arg.indexOf('=')

          if (eq === -1) {
            eq = arg.length
          }

          const name = arg.slice(2, eq)

          if (!single && !Object.prototype.hasOwnProperty.call(defaultOptions,
                name)) {
            obj['!?'].push(arg.slice(0, eq))

            return obj
          }

          if (single && eq === arg.length - 1) {
            obj[expect = name] = ''

            return obj
          }

          obj[name] = typeof defaultOptions[name] === 'boolean' &&
            eq === arg.length || arg.slice(eq + 1)

        } else {
          stop = true
        }
      } else if (expect) {
        obj[expect] = arg

      } else if (rest.length > 0) {
        obj[rest.shift()] = arg

      } else {
        obj['...'].push(arg)
      }

    } else if (single) {
      obj['!?'].push(args[index])
    }

    expect = null

    return obj
  },
  obj)
}

export function prompt(label, quiet) {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
      throw new Error('No TTY')
    }

    if (typeof quiet !== 'boolean') {
      quiet = false
    }

    if (typeof label === 'string') {
      process.stdout.write(label)
    }

    const rl = readline.createInterface({
      input: process.stdin,
      // The quiet argument is for things like passwords. It turns off standard
      // output so nothing is displayed.
      output: !quiet && process.stdout || null,
      terminal: true
    })

    rl.on('line', line => {
      try {
        rl.close()

        if (quiet) {
          process.stdout.write(os.EOL)
        }

        resolve(line)

      } catch (error) {
        reject(error)
      }
    })
  })
}

export function home() {
  return process.env[(process.platform === 'win32') ? 'USERPROFILE' : 'HOME']
}

export function streamHash(stream, algorithm, { encoding } = {}) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash(algorithm)

    if (typeof encoding === 'string') {
      hash.setEncoding(encoding)
    }

    stream.on('error', error => {
      hash.end()

      reject(error)
    })

    stream.on('end', () => {
      hash.end()

      resolve(hash.read())
    })

    stream.pipe(hash)
  })
}

// vim: et ts=2 sw=2
