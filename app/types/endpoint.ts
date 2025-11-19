export interface Endpoint {
  id: string;
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";
  route: string;
  description: string;
  version: string;
  service: string;
  tags: string[];
  latency: {
    avg: number;
    p95: number;
    p99: number;
  };
  errorRate: number;
  requestsToday: number;
  uptime: number;
  status: "healthy" | "warning" | "critical";
  deprecated: boolean;
  scopes: string[];
  rateLimit: {
    requests: number;
    window: string;
  };
  lastActivity: string;
  createdAt: string;
  updatedAt: string;
}

export interface EndpointMetrics {
  endpointId: string;
  timestamp: string;
  requests: number;
  errors: number;
  latency: number;
  statusCodes: Record<number, number>;
}

export interface EndpointCall {
  id: string;
  endpointId: string;
  timestamp: string;
  application: string;
  userId?: string;
  statusCode: number;
  latency: number;
  payload?: any;
  errorMessage?: string;
  userAgent?: string;
  ip?: string;
}

export interface EndpointSchema {
  parameters?: {
    name: string;
    type: string;
    required: boolean;
    description: string;
  }[];
  query?: {
    name: string;
    type: string;
    required: boolean;
    description: string;
  }[];
  body?: {
    type: string;
    required: boolean;
    schema: any;
    example?: any;
  };
  response?: {
    [statusCode: number]: {
      type: string;
      schema: any;
      example?: any;
    };
  };
}

export interface EndpointService {
  name: string;
  status: "connected" | "disconnected";
  endpoint?: string;
  version?: string;
}