import { z } from 'zod';

export const scanUrlSchema = z.object({
  url: z
    .string({ required_error: 'URL is required' })
    .trim()
    .min(1, 'URL cannot be empty')
    .url('Invalid URL format. Please provide a valid absolute URL (e.g., https://example.com)'),
});
