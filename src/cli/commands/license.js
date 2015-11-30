import fs   from 'fs'
import path from 'path'

export default function () {
  process.stdout.write(fs.readFileSync(path.resolve(__dirname, '..', '..', '..',
          'LICENSE')))
}

// vim: et ts=2 sw=2
