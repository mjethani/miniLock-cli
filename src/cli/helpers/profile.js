import path from 'path'

import { home } from '../../common/util'

import { Profile } from '../objects/profile'

let profile = null

function loadProfile() {
  try {
    profile = Profile.loadFromFile(path.resolve(home(), '.mlck',
          'profile.json'))
  } catch (error) {
    if (error instanceof SyntaxError) {
      console.error('WARNING: Profile data is corrupt.')
    }
  }
}

export function getProfile() {
  if (profile === null) {
    loadProfile()

    if (!profile) {
      profile = undefined
    }
  }

  return profile || null
}

// vim: et ts=2 sw=2
