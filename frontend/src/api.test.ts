import { describe, expect, it, vi } from 'vitest'
import { fetchApi } from './api'

describe('fetchApi', () => {
  it('returns typed JSON for successful responses', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ scenarios: ['synthetic_log'] }),
    }))

    await expect(fetchApi<{ scenarios: string[] }>('/api/scenarios')).resolves.toEqual({
      scenarios: ['synthetic_log'],
    })
  })

  it('uses the API error detail for failed responses', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 422,
      json: () => Promise.resolve({ detail: 'Unknown scheduler' }),
    }))

    await expect(fetchApi('/api/simulate')).rejects.toThrow('Unknown scheduler')
  })
})
