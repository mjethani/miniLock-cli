let debugFunc = null;

export default function debug(...rest) {
  if (debugFunc) {
    debugFunc(...rest);
  }
}

export function setDebugFunc(func) {
  debugFunc = func;
}

// vim: et ts=2 sw=2
