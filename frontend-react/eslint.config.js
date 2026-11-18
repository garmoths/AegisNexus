import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist', 'dist-crawler']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    rules: {
      // `motion.div` style namespaces and PascalCase components are used as values in JSX.
      '@typescript-eslint/no-unused-vars': ['error', { varsIgnorePattern: '^([A-Z_]|motion|AnimatePresence)', argsIgnorePattern: '^_' }],
    },
  },
  {
    // shadcn/ui files export cva variant helpers next to the component.
    files: ['src/components/ui/**/*.tsx', 'src/modules/shared.tsx'],
    rules: { 'react-refresh/only-export-components': 'off' },
  },
  {
    files: ['src/**/*.test.{ts,tsx}'],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
  },
])
