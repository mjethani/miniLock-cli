export default function promisify(thisArg, func) {
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

// vim: et ts=2 sw=2
