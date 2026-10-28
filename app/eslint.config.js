// SPDX-License-Identifier: GPL-3.0-or-later
import js from '@eslint/js'
import reactHooks from 'eslint-plugin-react-hooks'
import globals from 'globals'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist', 'coverage', 'src/api/generated.ts'] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: { globals: globals.browser },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      // C-CODE-06：Hooks 规则必须是 error
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      // C-SEC-10：禁止动态执行代码和注入 HTML
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-restricted-syntax': [
        'error',
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: '禁止 dangerouslySetInnerHTML（C-SEC-10），外部数据只能按纯文本渲染',
        },
      ],
    },
  },
  {
    // C-CODE-09：组件只能经 features/*/api.ts 的 hook 访问服务，不能直接调用 IPC
    files: ['src/**/*.tsx'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['@tauri-apps/api', '@tauri-apps/api/*'],
              message:
                '组件不能直接调用 Tauri（C-CODE-09），请使用 features/<领域>/api.ts 里的 hook',
            },
            {
              group: ['@/api/client', '**/api/client'],
              message:
                '组件不能直接调用 IPC 客户端（C-CODE-09），请使用 features/<领域>/api.ts 里的 hook',
            },
          ],
        },
      ],
    },
  },
  {
    files: ['*.config.{js,ts}'],
    languageOptions: { globals: globals.node },
  },
)
