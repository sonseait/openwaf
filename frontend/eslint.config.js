import js from "@eslint/js";
import globals from "globals";
import ts from "typescript-eslint";
import hooks from "eslint-plugin-react-hooks";
import refresh from "eslint-plugin-react-refresh";
export default ts.config(
  { ignores: ["dist", "node_modules", "playwright-report", "test-results"] },
  { files: ["**/*.{js,mjs}"], languageOptions: { globals: globals.node } },
  js.configs.recommended,
  ...ts.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
    plugins: { "react-hooks": hooks, "react-refresh": refresh },
    rules: {
      ...hooks.configs.recommended.rules,
      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "@mantine/core",
              importNames: ["Table"],
              message:
                "Use the shared DataTable component from src/DataTable.tsx.",
            },
          ],
        },
      ],
      "no-restricted-syntax": [
        "error",
        {
          selector:
            "JSXOpeningElement[name.type='JSXIdentifier'][name.name=/^(table|thead|tbody|tfoot|tr|th|td)$/]",
          message:
            "Use the shared DataTable component instead of raw table markup.",
        },
      ],
      "react-refresh/only-export-components": [
        "warn",
        { allowConstantExport: true },
      ],
    },
  },
);
