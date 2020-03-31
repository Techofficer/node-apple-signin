/**
 * This script is runned in a precommit and checks if any source files have changed and are staged and only then builds
 * doc files, so docs aren't build when you just update otherfiles that doesn't affect source code.
 */
import { execSync } from "child_process";
import fs from "fs";
import path from "path";

function hasGitStagedFilesFromPath(folderPath: string): boolean {
  const stagedFiles = execSync("git diff --name-only --cached", { encoding: "utf8" })
    .split("\n")
    .filter(Boolean)
    .filter((path) => path.startsWith(folderPath));
  return !!stagedFiles.length;
}

/**
 * Fixes issues where tpyedoc generate files startind with underscore aren't showing up in gh-pages
 * @link https://github.com/TypeStrong/typedoc/issues/620
 */
function fixGhDocsNotShowingGnereatedHtmlFiles(): void {
  const configPath = path.join(__dirname, "../docs/_config.yml");
  const configContents = `include:
  - "_*_.html"
  - "_*_.*.html"`;
  console.log(configPath, configContents);
  fs.writeFileSync(configPath, configContents, { encoding: "utf8" });
}

console.log("📕 Checking if need to build docs.");

const SOURCE_FILE_PATH = "src/";
const shouldBuildDocs = hasGitStagedFilesFromPath(SOURCE_FILE_PATH);
const forceBuild = process.env.FORCE_DOCS === "true";

if (forceBuild || shouldBuildDocs) {
  if (forceBuild) {
    console.log("📕 Force building docs regardles of source file state");
  } else {
    console.log("📕 Found staged changes to source files, build docs and adding docs to commit");
  }
  execSync("npm run docs", { stdio: "inherit" });
  fixGhDocsNotShowingGnereatedHtmlFiles();
  execSync("git add ./docs", { stdio: "inherit" });
  execSync("git add -u ./docs", { stdio: "inherit" });
  process.exit(0);
} else {
  console.log("📕 No staged changes found for source files, skipping building docs");
  process.exit(0);
}
