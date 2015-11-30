import { printHelp } from '../helpers/help'

export default function () {
  printHelp(process.argv[2] === 'help' && process.argv[3])
}

// vim: et ts=2 sw=2
