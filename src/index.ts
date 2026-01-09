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
  // Create a single, reusable service instance
  const service = new CognitoService(config);

  return {
    // Service instance
    service,

    // Configuration presets
    configs: CognitoConfigs,

    // Utility functions
    utils: {
      extractTokens,
    },

    // Quick access methods (delegates to service)
    async register(data: import('./types/index.js').UserRegistrationData) {
      return service.registerUser(data);
    },

    async login(data: import('./types/index.js').UserLoginData) {
      return service.loginUser(data);
    },

    async confirmRegistration(data: import('./types/index.js').ConfirmRegistrationData) {
      return service.confirmUserRegistration(data);
    },

    async forgotPassword(data: import('./types/index.js').ForgotPasswordData) {
      return service.initiateForgotPassword(data);
    },

    async verifyToken(token: string) {
      return service.verifyToken(token);
    },

    async verifyAccessToken(token: string) {
      return service.verifyAccessToken(token);
    },

    async verifyIdToken(token: string) {
      return service.verifyIdToken(token);
    },

    async getUserFromToken(accessToken: string) {
      return service.getUserFromToken(accessToken);
    },

    async refreshTokens(refreshToken: string) {
      return service.refreshTokens(refreshToken);
    },

    async revokeToken(token: string) {
      return service.revokeToken(token);
    },
    async adminCreateUser(data: import('./types/index.js').AdminCreateUserData) {
      return service.adminCreateUser(data);
    },
    async adminDeleteUser(params: { username: string }) {
      return service.adminDeleteUser(params);
    },
    async adminDisableUser(data: import('./types/index.js').AdminDisableUserData) {
      return service.adminDisableUser(data);
    },
    async adminEnableUser(data: import('./types/index.js').AdminEnableUserData) {
      return service.adminEnableUser(data);
    },
    async adminUpdateUserAttributes(data: import('./types/index.js').AdminUpdateUserAttributesData) {
      return service.adminUpdateUserAttributes(data);
    },
    async respondToNewPasswordChallenge(data: import('./types/index.js').RespondToNewPasswordChallengeData) {
      return service.respondToNewPasswordChallenge(data);
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
      adminDeleteUser: this.cognitoService.adminDeleteUser.bind(this.cognitoService),
      adminDisableUser: this.cognitoService.adminDisableUser.bind(this.cognitoService),
      adminEnableUser: this.cognitoService.adminEnableUser.bind(this.cognitoService),
      adminUpdateUserAttributes: this.cognitoService.adminUpdateUserAttributes.bind(this.cognitoService),
      respondToNewPasswordChallenge: this.cognitoService.respondToNewPasswordChallenge.bind(this.cognitoService),

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