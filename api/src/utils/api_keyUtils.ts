import { randomBytes } from 'crypto';
import { ApiKeyCategory } from '../models/api_keyModels';

export const generateApiKey = (category: ApiKeyCategory): string => {
  const timestamp = Date.now().toString(36);
  const randomBytesStr = randomBytes(24).toString('hex');
  return `sk_${category}_${timestamp}_${randomBytesStr}`;
};

export const validateApiKeyFormat = (apiKey: string): boolean => {
  const skPattern = /^sk_(client|server|database)_[a-z0-9]+_[a-f0-9]{48}$/;
  return skPattern.test(apiKey);
};

export const extractCategoryFromKey = (apiKey: string): ApiKeyCategory | null => {
  const match = apiKey.match(/^sk_(client|server|database)_/);
  if (match) {
    return match[1] as ApiKeyCategory;
  }
  return null;
};

export const maskApiKey = (apiKey: string): string => {
  if (!apiKey.startsWith('sk_')) {
    return apiKey;
  }
  
  const parts = apiKey.split('_');
  if (parts.length < 4) {
    return apiKey;
  }
  
  const [prefix, category, timestamp, hash] = parts;
  const maskedHash = hash.substring(0, 8) + '...' + hash.substring(hash.length - 4);
  
  return `${prefix}_${category}_${timestamp}_${maskedHash}`;
};