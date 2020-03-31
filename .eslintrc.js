module.exports = {
  env: {
    node: true,
    es6: true
  },
  parser: "@typescript-eslint/parser",
  plugins: ["prettier", "@typescript-eslint"],
  extends: [
    "standard",
    /**
     * Extend standard by adding typescript specific rules
     */
    "plugin:@typescript-eslint/recommended",
    /**
     * Use prettier/@typescript-eslint to disable prettier conflicting
     * eslint rules set by @typescript-eslint/eslint-plugin
     */
    "prettier/@typescript-eslint",
    /**
     * Enables eslint-plugin-prettier and displays prettier errors as eslint
     * errors instead of running eslint and prettier separate.
     * ⚠️ Make sure this is always the last configuration in the extends array!
     */
    "plugin:prettier/recommended"
  ]
};
