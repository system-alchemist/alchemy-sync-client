import { defineConfig } from 'vitest/config';

// The client is framework-free, so its tests need no plugins or aliases.
export default defineConfig({
	test: { include: ['src/**/*.test.ts'], environment: 'node' }
});
