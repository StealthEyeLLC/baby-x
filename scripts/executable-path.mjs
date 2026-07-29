import { accessSync, constants, statSync } from 'node:fs';
import { delimiter, join } from 'node:path';

const executableName = /^[A-Za-z0-9._+-]+$/u;

export function executableFromPath(name, pathValue = process.env.PATH ?? '') {
  if (!executableName.test(name)) throw new Error(`invalid executable name: ${name}`);
  for (const directory of pathValue.split(delimiter)) {
    if (directory.length === 0) continue;
    const candidate = join(directory, name);
    try {
      accessSync(candidate, constants.X_OK);
      if (statSync(candidate).isFile()) return candidate;
    } catch {
      // Continue through the declared PATH only.
    }
  }
  return '';
}
