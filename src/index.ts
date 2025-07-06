// src/index.ts
// src/index.ts - Main export file
export { CognitoService, CognitoConfigs } from './services/cognito';
export { CognitoConfig, PackageConfig } from './config/packageConfig';

// Ensures all shared interfaces are available
export * from "./types";

// Exporting all functions for easier access
export { extractTokens } from "./utils/tokenManager";


