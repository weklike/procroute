// SPDX-License-Identifier: GPL-3.0-or-later
import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import App from './App'

describe('App', () => {
  it('renders the product name from i18n resources', () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: 'ProcRoute' })).toBeInTheDocument()
  })
})
