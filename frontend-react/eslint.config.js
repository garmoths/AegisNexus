import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist', 'dist-crawler']),
  {
    files: ['**/*.{js,jsx}'],
    extends: [
      js.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
      parserOptions: {
        ecmaVersion: 'latest',
        ecmaFeatures: { jsx: true },
        sourceType: 'module',
      },
    },
    rules: {
      // `motion` ve `AnimatePresence` JSX namespace pattern (örn. <motion.div>) ile
      // kullanıldığı için, ESLint default kuralı bu importları yanlışlıkla unused olarak işaretliyor.
      // Aşağıdaki ignorePattern bu pattern'i ve standart uppercase component naming'i kapsar.
      'no-unused-vars': ['error', { varsIgnorePattern: '^([A-Z_]|motion|AnimatePresence)' }],
    },
  },
  {
    // shadcn/ui bileşen dosyaları, bileşenin yanında cva varyant fonksiyonlarını da
    // dışa aktarır (buttonVariants vb.). Bu, kütüphane dosyaları için kabul edilir.
    files: ['src/components/ui/**/*.{js,jsx}'],
    rules: {
      'react-refresh/only-export-components': 'off',
    },
  },
])
