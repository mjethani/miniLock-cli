import fs   from 'fs'
import path from 'path'

export function printUsage() {
  try {
    const help = fs.readFileSync(path.resolve(__dirname, '..', '..', '..',
          'help', 'default.help'), 'utf8')
    process.stderr.write(help.split('\n\n')[0] + '\n\n')
  } catch (error) {
  }
}

export function printHelp(topic) {
  try {
    const help = fs.readFileSync(path.resolve(__dirname, '..', '..', '..',
          'help', `${topic || 'default'}.help`), 'utf8')
    process.stdout.write(help)
  } catch (error) {
    printUsage()
  }
}

// vim: et ts=2 sw=2
