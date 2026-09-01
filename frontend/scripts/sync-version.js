// 讓前端 package.json 的 version 以 pyproject.toml 為唯一事實來源。
// build 前執行(prebuild),把 ../pyproject.toml 的 [project].version 同步到 package.json,
// 避免前端獨立維護一份會漂移的版本號。
//
// 注意:UI 顯示的版本是執行期打 /system/version 取得(後端 version.py 讀 pyproject),
// 本腳本只負責讓「建置產物 metadata」也對齊 pyproject,不影響顯示邏輯。

import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const pyprojectPath = resolve(here, '../../pyproject.toml')
const packagePath = resolve(here, '../package.json')

// 極簡解析:只抓 [project] 區段內第一個 version = "x.y.z"
function readPyprojectVersion(text) {
  const projectSection = text.split(/^\[/m).find((s) => s.startsWith('project]'))
  const source = projectSection ?? text
  const m = source.match(/^\s*version\s*=\s*["']([^"']+)["']/m)
  return m ? m[1] : null
}

const version = readPyprojectVersion(readFileSync(pyprojectPath, 'utf-8'))
if (!version) {
  console.warn('[sync-version] pyproject.toml 找不到 version,略過同步')
  process.exit(0)
}

const pkg = JSON.parse(readFileSync(packagePath, 'utf-8'))
if (pkg.version !== version) {
  pkg.version = version
  writeFileSync(packagePath, JSON.stringify(pkg, null, 2) + '\n', 'utf-8')
  console.log(`[sync-version] package.json version -> ${version}(對齊 pyproject.toml)`)
} else {
  console.log(`[sync-version] package.json version 已是 ${version}`)
}
