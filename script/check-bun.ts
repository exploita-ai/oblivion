const expected = (await Bun.file(new URL("../package.json", import.meta.url)).json()).packageManager.slice(4)

if (Bun.version !== expected) {
  console.error(`This repository requires Bun ${expected}; current Bun is ${Bun.version}.`)
  process.exit(1)
}

export {}
