import { Request, Response } from 'express';

export interface ApiResponseData<T = any> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
  pagination?: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

export class ApiResponse {
  static success<T>(
    res: Response,
    data: T,
    message: string = 'Success',
    statusCode: number = 200
  ): Response {
    const response: ApiResponseData<T> = {
      success: true,
      data,
      message,
    };

    return res.status(statusCode).json(response);
  }

  static error(
    res: Response,
    message: string,
    statusCode: number = 500,
    error?: any
  ): Response {
    const response: ApiResponseData = {
      success: false,
      error: error || message,
      message,
    };

    return res.status(statusCode).json(response);
  }

  static paginated<T>(
    res: Response,
    data: T[],
    pagination: {
      page: number;
      limit: number;
      total: number;
      pages: number;
    },
    message: string = 'Data retrieved successfully'
  ): Response {
    const response: ApiResponseData<T[]> = {
      success: true,
      data,
      message,
      pagination,
    };

    return res.status(200).json(response);
  }
}