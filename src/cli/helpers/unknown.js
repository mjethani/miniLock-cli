import { die, findCloseMatches } from '../../common/util'

import { printUsage } from './help'

function printClosestMatches(string, candidateList) {
  const closeMatches = findCloseMatches(string, candidateList, {
    distanceThreshold: 2
  })

  if (closeMatches.length > 1) {
    console.error('Did you mean one of these?')
  } else if (closeMatches.length === 1) {
    console.error('Did you mean this?')
  }

  for (let match of closeMatches) {
    console.error('\t' + match)
  }
}

export function handleUnknownCommand(command, knownCommands) {
  if (command) {
    console.error(`Unknown command '${command}'.\n\nSee 'mlck --help'.\n`)

    // Find and display close matches using Levenshtein distance.
    printClosestMatches(command, knownCommands)
  } else {
    printUsage()
  }

  die()
}

export function handleUnknownOption(option, knownOptions) {
  console.error(`Unknown option '${option}'.\n\nSee 'mlck --help'.\n`)

  if (option.slice(0, 2) === '--') {
    // Find and display close matches using Levenshtein distance.
    printClosestMatches(option.slice(2), knownOptions)
  }

  die()
}

// vim: et ts=2 sw=2
