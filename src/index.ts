// src/index.ts
// src/index.ts - Main export file
export { CognitoService, CognitoConfigs } from './services/cognito.js';
export { CognitoConfig, PackageConfig } from './config/packageConfig.js';

// Ensures all shared interfaces are available
export * from './types/index.js';

// Exporting functions for easier access
export { extractTokens } from "./utils/tokenManager.js";


