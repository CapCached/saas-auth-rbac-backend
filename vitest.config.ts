import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      include: [
        "src/security/access-token.ts",
        "src/security/opaque-token.ts",
        "src/security/password.ts",
      ],
      provider: "v8",
      reporter: ["text", "lcov"],
      thresholds: {
        branches: 75,
        functions: 80,
        lines: 80,
        statements: 80,
      },
    },
    environment: "node",
    include: ["tests/**/*.test.ts"],
    mockReset: true,
    restoreMocks: true,
    testTimeout: 15_000,
  },
});
