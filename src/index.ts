// src/index.ts
// Main entry point with global import solution
import { CognitoService, CognitoConfigs } from './services/cognito.js';
import { CognitoConfig, PackageConfig } from './config/packageConfig.js';
import { extractTokens } from "./utils/tokenManager.js";

// Re-export all types
export * from './types/index.js';

// Traditional exports (keep for backward compatibility)
export { CognitoService, CognitoConfigs, CognitoConfig, PackageConfig, extractTokens };

// NEW: Global factory function for simplified usage
export default function createCognito(config: Partial<CognitoConfig>) {
  return {
    // Service instance
    service: new CognitoService(config),
    
    // Configuration presets
    configs: CognitoConfigs,
    
    // Utility functions
    utils: {
      extractTokens,
    },
    
    // Quick access methods (delegates to service)
    async register(data: import('./types/index.js').UserRegistrationData) {
      return new CognitoService(config).registerUser(data);
    },
    
    async login(data: import('./types/index.js').UserLoginData) {
      return new CognitoService(config).loginUser(data);
    },
    
    async confirmRegistration(data: import('./types/index.js').ConfirmRegistrationData) {
      return new CognitoService(config).confirmUserRegistration(data);
    },
    
    async forgotPassword(data: import('./types/index.js').ForgotPasswordData) {
      return new CognitoService(config).initiateForgotPassword(data);
    },
    
    async verifyToken(token: string) {
      return new CognitoService(config).verifyToken(token);
    },
    
    async verifyAccessToken(token: string) {
      return new CognitoService(config).verifyAccessToken(token);
    },
    
    async verifyIdToken(token: string) {
      return new CognitoService(config).verifyIdToken(token);
    },
    
    async getUserFromToken(accessToken: string) {
      return new CognitoService(config).getUserFromToken(accessToken);
    },
    
    async refreshTokens(refreshToken: string) {
      return new CognitoService(config).refreshTokens(refreshToken);
    },
    
    async revokeToken(token: string) {
      return new CognitoService(config).revokeToken(token);
    },
    async adminCreateUser(data: import('./types/index.js').AdminCreateUserData) {
      return new CognitoService(config).adminCreateUser(data);
    },
  };
}

// Alternative: Class-based global API
export class AWSForge {
  private cognitoService: CognitoService;
  
  constructor(config: Partial<CognitoConfig>) {
    this.cognitoService = new CognitoService(config);
  }
  
  // Cognito methods
  get cognito() {
    return {
      register: this.cognitoService.registerUser.bind(this.cognitoService),
      login: this.cognitoService.loginUser.bind(this.cognitoService),
      confirmRegistration: this.cognitoService.confirmUserRegistration.bind(this.cognitoService),
      forgotPassword: this.cognitoService.initiateForgotPassword.bind(this.cognitoService),
      confirmForgotPassword: this.cognitoService.confirmForgotPassword.bind(this.cognitoService),
      changePassword: this.cognitoService.changePassword.bind(this.cognitoService),
      deleteUser: this.cognitoService.deleteUser.bind(this.cognitoService),
      resendConfirmationCode: this.cognitoService.resendConfirmationCode.bind(this.cognitoService),
      adminCreateUser: this.cognitoService.adminCreateUser.bind(this.cognitoService),
      
      // Token methods
      verifyToken: this.cognitoService.verifyToken.bind(this.cognitoService),
      verifyAccessToken: this.cognitoService.verifyAccessToken.bind(this.cognitoService),
      verifyIdToken: this.cognitoService.verifyIdToken.bind(this.cognitoService),
      getUserFromToken: this.cognitoService.getUserFromToken.bind(this.cognitoService),
      refreshTokens: this.cognitoService.refreshTokens.bind(this.cognitoService),
      revokeToken: this.cognitoService.revokeToken.bind(this.cognitoService),
    };
  }
  
  // Utils
  get utils() {
    return {
      extractTokens,
    };
  }
  
  // Configs
  static get configs() {
    return CognitoConfigs;
  }
}

// Export as named export too
export { createCognito };

// Re-export the service for those who prefer the original approach
export { CognitoService as Cognito };