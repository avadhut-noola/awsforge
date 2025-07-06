"use strict";
// src/services/cognito.ts
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerUser = registerUser;
exports.confirmUserRegistration = confirmUserRegistration;
exports.loginUser = loginUser;
exports.initiateForgotPassword = initiateForgotPassword;
var client_cognito_identity_provider_1 = require("@aws-sdk/client-cognito-identity-provider");
var client = new client_cognito_identity_provider_1.CognitoIdentityProviderClient({
    region: process.env.AWS_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY,
        secretAccessKey: process.env.AWS_SECRET_KEY,
    },
});
var CLIENT_ID = process.env.CLIENT_ID;
// Register a new user (UNCONFIRMED)
function registerUser(_a) {
    return __awaiter(this, arguments, void 0, function (_b) {
        var userAttributes, command;
        var username = _b.username, password = _b.password, email = _b.email, firstName = _b.firstName, lastName = _b.lastName, phoneNumber = _b.phoneNumber, _c = _b.customAttributes, customAttributes = _c === void 0 ? {} : _c;
        return __generator(this, function (_d) {
            userAttributes = __spreadArray(__spreadArray(__spreadArray(__spreadArray([
                { Name: "email", Value: email },
                { Name: "preferred_username", Value: username }
            ], (firstName ? [{ Name: "given_name", Value: firstName }] : []), true), (lastName ? [{ Name: "family_name", Value: lastName }] : []), true), (phoneNumber ? [{ Name: "phone_number", Value: phoneNumber }] : []), true), Object.entries(customAttributes).map(function (_a) {
                var key = _a[0], value = _a[1];
                return ({
                    Name: "custom:".concat(key),
                    Value: value,
                });
            }), true);
            command = new client_cognito_identity_provider_1.SignUpCommand({
                ClientId: CLIENT_ID,
                Username: email,
                Password: password,
                UserAttributes: userAttributes,
            });
            return [2 /*return*/, client.send(command)];
        });
    });
}
//Confirm user registration with email OTP
function confirmUserRegistration(_a) {
    return __awaiter(this, arguments, void 0, function (_b) {
        var command;
        var username = _b.username, confirmationCode = _b.confirmationCode;
        return __generator(this, function (_c) {
            command = new client_cognito_identity_provider_1.ConfirmSignUpCommand({
                ClientId: CLIENT_ID,
                Username: username,
                ConfirmationCode: confirmationCode,
            });
            return [2 /*return*/, client.send(command)];
        });
    });
}
// Login user after confirmation
function loginUser(_a) {
    return __awaiter(this, arguments, void 0, function (_b) {
        var command;
        var username = _b.username, password = _b.password;
        return __generator(this, function (_c) {
            command = new client_cognito_identity_provider_1.InitiateAuthCommand({
                AuthFlow: client_cognito_identity_provider_1.AuthFlowType.USER_PASSWORD_AUTH,
                ClientId: CLIENT_ID,
                AuthParameters: {
                    USERNAME: username,
                    PASSWORD: password,
                },
            });
            return [2 /*return*/, client.send(command)];
        });
    });
}
// Forgot Password Initiation
function initiateForgotPassword(_a) {
    return __awaiter(this, arguments, void 0, function (_b) {
        var command;
        var username = _b.username;
        return __generator(this, function (_c) {
            command = new client_cognito_identity_provider_1.ForgotPasswordCommand({
                ClientId: CLIENT_ID,
                Username: username,
            });
            return [2 /*return*/, client.send(command)];
        });
    });
}
