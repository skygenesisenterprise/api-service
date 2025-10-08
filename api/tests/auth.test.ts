import request from 'supertest';
import app from '../index';

describe('POST /api/auth', () => {
  it('should authenticate user', async () => {
    const response = await request(app)
      .post('/api/auth')
      .send({ username: 'testuser', password: 'testpassword' });

    expect(response.status).toBe(200);
    expect(response.body.message).toBe('Authentication successful');
  });

  it('should return error if username or password is missing', async () => {
    const response = await request(app)
      .post('/api/auth')
      .send({ username: 'testuser' });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe('Username and password are required');
  });
});