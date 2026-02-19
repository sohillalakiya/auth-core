import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals.map((config) => ({
    ...config,
    rules: {
      ...config.rules,
      "react/*": "off",
    },
  })),
  ...nextTs.map((config) => ({
    ...config,
    rules: {
      ...config.rules,
      "react/*": "off",
    },
  })),
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
  ]),
]);

export default eslintConfig;
