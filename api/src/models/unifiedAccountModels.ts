export interface IUnifiedAccount {
  id: string;
  globalId: string; // Unique identifier across ecosystem
  primaryEmail: string;
  username?: string;
  phoneNumber?: string;
  profile: {
    firstName?: string;
    lastName?: string;
    avatar?: string;
    timezone?: string;
    language?: string;
  };
  preferences: {
    theme?: 'light' | 'dark' | 'auto';
    notifications: {
      email: boolean;
      push: boolean;
      sms: boolean;
    };
    privacy: {
      profileVisibility: 'public' | 'private' | 'organizations';
      dataSharing: boolean;
    };
  };
  status: 'active' | 'suspended' | 'deleted';
  isVerified: boolean;
  lastLoginAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface IAccountIdentifier {
  id: string;
  accountId: string;
  type: 'email' | 'phone' | 'username' | 'oauth';
  value: string;
  provider?: string; // For OAuth: 'google', 'microsoft', 'github', etc.
  providerId?: string; // External provider user ID
  isPrimary: boolean;
  isVerified: boolean;
  createdAt: Date;
}

export interface IOrganizationMembership {
  id: string;
  accountId: string;
  organizationId: string;
  role: 'owner' | 'admin' | 'member' | 'viewer';
  permissions: string[];
  isActive: boolean;
  joinedAt: Date;
}

export interface ICreateUnifiedAccountRequest {
  email: string;
  username?: string;
  phoneNumber?: string;
  password?: string;
  profile?: {
    firstName?: string;
    lastName?: string;
    timezone?: string;
    language?: string;
  };
  organizationId?: string; // Auto-create first organization if provided
}

export interface ILinkIdentifierRequest {
  type: 'email' | 'phone' | 'username' | 'oauth';
  value: string;
  provider?: string;
  providerId?: string;
  isPrimary?: boolean;
}

export interface IAuthResponse {
  account: IUnifiedAccount;
  tokens: {
    accessToken: string;
    refreshToken: string;
    idToken?: string;
  };
  memberships: IOrganizationMembership[];
}

export interface ISession {
  id: string;
  accountId: string;
  tokenHash: string;
  deviceInfo?: {
    userAgent: string;
    ip: string;
    device: string;
    browser: string;
  };
  isActive: boolean;
  expiresAt: Date;
  createdAt: Date;
  lastAccessAt: Date;
}