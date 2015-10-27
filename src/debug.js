let debugFunc = null;

export default function debug() {
  if (debugFunc) {
    debugFunc.apply(null, arguments);
  }
}

export function setDebugFunc(func) {
  debugFunc = func;
}

// vim: et ts=2 sw=2
