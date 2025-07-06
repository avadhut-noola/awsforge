"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.extractTokens = exports.initiateForgotPassword = exports.loginUser = exports.confirmUserRegistration = exports.registerUser = void 0;
// src/index.ts
var dotenv_1 = require("dotenv");
dotenv_1.default.config();
var cognito_1 = require("./services/cognito");
Object.defineProperty(exports, "registerUser", { enumerable: true, get: function () { return cognito_1.registerUser; } });
Object.defineProperty(exports, "confirmUserRegistration", { enumerable: true, get: function () { return cognito_1.confirmUserRegistration; } });
Object.defineProperty(exports, "loginUser", { enumerable: true, get: function () { return cognito_1.loginUser; } });
Object.defineProperty(exports, "initiateForgotPassword", { enumerable: true, get: function () { return cognito_1.initiateForgotPassword; } });
var tokenManager_1 = require("./utils/tokenManager");
Object.defineProperty(exports, "extractTokens", { enumerable: true, get: function () { return tokenManager_1.extractTokens; } });
// Ensures all shared interfaces are available
__exportStar(require("./types"), exports);
