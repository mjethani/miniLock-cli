import { parseArgs } from '../common/util'

import { setDebugFunc } from '../common/debug'

import { handleUnknownCommand, handleUnknownOption } from './helpers/unknown'

function handleCommand(command) {
  const args = process.argv[2].slice(0, 2) === '--' ? [] : process.argv.slice(3)

  require(`./commands/${command}`).execute(args)
}

export function run() {
  if (process.argv[2] === '--debug') {
    process.argv.splice(2, 1)

    setDebugFunc((...rest) => {
      console.error(...rest)
    })
  }

  const defaultOptions = {
    'help':    false,
    'version': false,
    'license': false,
  }

  const shortcuts = {
    '-h': '--help',
    '-?': '--help',
    '-V': '--version',
  }

  const options = parseArgs([ process.argv[2] || '' ], defaultOptions,
    shortcuts)

  if (options['!?'].length > 0) {
    handleUnknownOption(options['!?'][0], Object.keys(defaultOptions))
  }

  let {
    'help':    help,
    'version': version,
    'license': license,
  } = options

  if (help) {
    handleCommand('help')

    return

  } else if (version) {
    handleCommand('version')

    return

  } else if (license) {
    handleCommand('license')

    return
  }

  const command = process.argv[2]

  switch (command) {
  case 'id':
  case 'encrypt':
  case 'decrypt':
  case 'help':
  case 'version':
  case 'license':
    handleCommand(command)

    break

  default:
    handleUnknownCommand(command, [
      'id',
      'encrypt',
      'decrypt',
      'help',
      'version',
      'license',
    ])
  }
}

function main() {
  run()
}

if (require.main === module) {
  main()
}

// vim: et ts=2 sw=2
