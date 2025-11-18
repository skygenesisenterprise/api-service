export interface ILoginRequest {
  email: string;
  password: string;
}

export interface IRegisterRequest {
  email: string;
  password: string;
  fullName?: string;
  organizationId?: string;
}

export interface IAuthResponse {
  user: {
    id: string;
    email: string;
    fullName?: string;
    organizationId?: string;
  };
  token: string;
  refreshToken?: string;
}

export interface IUser {
  id: string;
  email: string;
  fullName?: string;
  organizationId?: string;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}