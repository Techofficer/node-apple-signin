/**
 * This script is runned in a precommit and checks if any source files have changed and are staged and only then builds
 * doc files, so docs aren't build when you just update otherfiles that doesn't affect source code.
 */
import { execSync } from "child_process";

function hasGitStagedFilesFromPath(folderPath: string): boolean {
  const stagedFiles = execSync("git diff --name-only --cached", { encoding: "utf8" })
    .split("\n")
    .filter(Boolean)
    .filter((path) => path.startsWith(folderPath));
  return !!stagedFiles.length;
}

console.log("📕 Checking if need to build docs.");

const SOURCE_FILE_PATH = "src/";
const shouldBuildDocs = hasGitStagedFilesFromPath(SOURCE_FILE_PATH);

if (process.env.FORCE_DOCS === "true" || shouldBuildDocs) {
  console.log("📕 Found staged changes to source files, build docs and adding docs to commit");
  execSync("npm run docs", { stdio: "inherit" });
  execSync("git add ./docs", { stdio: "inherit" });
  execSync("git add -u ./docs", { stdio: "inherit" });
  process.exit(0);
} else {
  console.log("📕 No staged changes found for source files, skipping building docs");
  process.exit(0);
}
