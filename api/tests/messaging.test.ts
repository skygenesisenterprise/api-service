import request from 'supertest';
import app from '../index';

describe('Messaging API', () => {
  let authToken: string;
  let conversationId: string;
  let messageId: string;
  let testUserId: string = 'test-user-id'; // Mock user ID for testing

  beforeAll(async () => {
    // Mock authentication - in a real app, you'd get a real token
    authToken = 'mock-jwt-token';
  });

  describe('POST /api/messaging/organizations/:organization_id/conversations', () => {
    it('should create a new conversation', async () => {
      const response = await request(app)
        .post('/api/messaging/organizations/test-org/conversations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          title: 'Test Conversation',
          type: 'group',
          participant_ids: [testUserId, 'another-user-id']
        });

      expect(response.status).toBe(201);
      expect(response.body.message).toBe('Conversation created successfully');
      expect(response.body.data).toHaveProperty('id');
      conversationId = response.body.data.id;
    });

    it('should return error for missing participants', async () => {
      const response = await request(app)
        .post('/api/messaging/organizations/test-org/conversations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          title: 'Test Conversation',
          type: 'group'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('participant_ids must be an array');
    });
  });

  describe('GET /api/messaging/conversations', () => {
    it('should get user conversations', async () => {
      const response = await request(app)
        .get('/api/messaging/conversations')
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });
  });

  describe('GET /api/messaging/conversations/:conversation_id', () => {
    it('should get a specific conversation', async () => {
      const response = await request(app)
        .get(`/api/messaging/conversations/${conversationId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.data.id).toBe(conversationId);
    });
  });

  describe('POST /api/messaging/conversations/:conversation_id/messages', () => {
    it('should send a message', async () => {
      const response = await request(app)
        .post(`/api/messaging/conversations/${conversationId}/messages`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          content: 'Hello, this is a test message!',
          message_type: 'text'
        });

      expect(response.status).toBe(201);
      expect(response.body.message).toBe('Message sent successfully');
      expect(response.body.data).toHaveProperty('id');
      messageId = response.body.data.id;
    });

    it('should return error for empty message', async () => {
      const response = await request(app)
        .post(`/api/messaging/conversations/${conversationId}/messages`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({});

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Message content is required');
    });
  });

  describe('GET /api/messaging/conversations/:conversation_id/messages', () => {
    it('should get messages from conversation', async () => {
      const response = await request(app)
        .get(`/api/messaging/conversations/${conversationId}/messages`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });

    it('should support pagination', async () => {
      const response = await request(app)
        .get(`/api/messaging/conversations/${conversationId}/messages?limit=10&offset=0`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });
  });

  describe('PUT /api/messaging/messages/:message_id', () => {
    it('should update a message', async () => {
      const response = await request(app)
        .put(`/api/messaging/messages/${messageId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          content: 'Updated message content'
        });

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Message updated successfully');
    });
  });

  describe('POST /api/messaging/messages/:message_id/reactions', () => {
    it('should add a reaction to message', async () => {
      const response = await request(app)
        .post(`/api/messaging/messages/${messageId}/reactions`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          reaction: '👍'
        });

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Reaction added successfully');
    });
  });

  describe('POST /api/messaging/messages/:message_id/read', () => {
    it('should mark message as read', async () => {
      const response = await request(app)
        .post(`/api/messaging/messages/${messageId}/read`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Message marked as read');
    });
  });

  describe('POST /api/messaging/conversations/:conversation_id/read', () => {
    it('should mark conversation as read', async () => {
      const response = await request(app)
        .post(`/api/messaging/conversations/${conversationId}/read`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Conversation marked as read');
    });
  });

  describe('DELETE /api/messaging/messages/:message_id/reactions/:reaction', () => {
    it('should remove a reaction from message', async () => {
      const response = await request(app)
        .delete(`/api/messaging/messages/${messageId}/reactions/${encodeURIComponent('👍')}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Reaction removed successfully');
    });
  });

  describe('POST /api/messaging/conversations/:conversation_id/participants', () => {
    it('should add a participant to conversation', async () => {
      const response = await request(app)
        .post(`/api/messaging/conversations/${conversationId}/participants`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          user_id: 'new-participant-id'
        });

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Participant added successfully');
    });
  });

  describe('DELETE /api/messaging/conversations/:conversation_id/participants/:user_id', () => {
    it('should remove a participant from conversation', async () => {
      const response = await request(app)
        .delete(`/api/messaging/conversations/${conversationId}/participants/new-participant-id`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Participant removed successfully');
    });
  });

  describe('DELETE /api/messaging/messages/:message_id', () => {
    it('should delete a message', async () => {
      const response = await request(app)
        .delete(`/api/messaging/messages/${messageId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Message deleted successfully');
    });
  });

  describe('DELETE /api/messaging/conversations/:conversation_id', () => {
    it('should delete a conversation', async () => {
      const response = await request(app)
        .delete(`/api/messaging/conversations/${conversationId}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Conversation deleted successfully');
    });
  });

  describe('Authentication', () => {
    it('should return 401 for unauthenticated requests', async () => {
      const response = await request(app)
        .get('/api/messaging/conversations');

      expect(response.status).toBe(401);
      expect(response.body.error).toBe('Access token required');
    });
  });
});