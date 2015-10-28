let debugHandler = null;

export default function debug(...rest) {
  if (debugHandler) {
    debugHandler(...rest);
  }
}

export function installDebugHandler(handler) {
  if (debugHandler) {
    throw new Error('Debug handler already installed');
  }

  debugHandler = handler;
}

export function uninstallDebugHandler() {
  const handler = debugHandler;

  debugHandler = null;

  return handler;
}

// vim: et ts=2 sw=2
