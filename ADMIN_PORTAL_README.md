# Admin Portal

The Sky Genesis Enterprise API Service includes a comprehensive web-based admin portal for managing API keys, monitoring usage, and administering the messaging platform.

## Features

- **🔐 Secure Authentication**: API key-based access to admin functions
- **🔑 API Key Management**: Create, view, revoke, and monitor API keys
- **📊 Analytics Dashboard**: Real-time monitoring of API usage and performance
- **🏢 Organization Management**: Administer organizations and their settings
- **⚙️ User Preferences**: Customizable interface and notification settings
- **📱 Responsive Design**: Works on desktop and mobile devices
- **🌙 Dark Mode Support**: Automatic dark/light theme switching

## Getting Started

### Prerequisites

- Running API backend server
- At least one API key with admin permissions
- Modern web browser

### Access the Portal

1. Start the Next.js development server:
   ```bash
   cd app
   npm run dev
   ```

2. Open your browser and navigate to `http://localhost:3000`

3. Click "Access Admin Portal" on the homepage

4. Enter your Organization ID and API key with admin permissions

## Portal Sections

### Dashboard

The main dashboard provides an overview of your API ecosystem:

- **Key Metrics**: Total API keys, active keys, usage statistics
- **Recent Activity**: Latest API key creations and modifications
- **Quick Actions**: Fast access to common administrative tasks

### API Keys Management

Comprehensive API key administration:

#### Creating API Keys
1. Navigate to "API Keys" in the sidebar
2. Click "Create API Key"
3. Fill in the required information:
   - **Label**: Human-readable name for the key
   - **Permissions**: Select appropriate permissions
   - **Quota Limit**: Maximum API calls allowed
4. Click "Create Key"
5. **Important**: Save the generated API key securely - it won't be shown again

#### Managing API Keys
- **View Details**: See key permissions, usage statistics, and creation date
- **Monitor Usage**: Track API calls against quota limits
- **Revoke Keys**: Immediately disable API keys when needed

#### Permissions Explained
- `read`: Access to view conversations and messages
- `write`: Create and modify conversations and messages
- `admin`: Full administrative access including API key management

### Organizations

Manage organization settings and information:

- View organization details
- Monitor organization-wide statistics
- Configure organization-specific settings

### Analytics

Monitor API performance and usage patterns:

- **Request Metrics**: Total requests, success rates, error rates
- **Endpoint Usage**: Most frequently accessed API endpoints
- **Response Status**: Breakdown of HTTP status codes
- **Usage Over Time**: Historical usage patterns
- **Top API Keys**: Highest-usage keys by organization

### Settings

Customize your admin portal experience:

- **Theme**: Light, dark, or system preference
- **Notifications**: Enable/disable system notifications
- **Language**: Interface language selection
- **Timezone**: Display timezone for dates and times

## Security Features

### Authentication
- API key validation on every request
- Organization-based access control
- Secure key storage in browser localStorage
- Automatic session management

### Permissions
- Granular permission system
- Admin-only access to sensitive operations
- Permission validation on all API calls

### Data Protection
- No sensitive data stored in browser
- Secure HTTPS communication (in production)
- Automatic logout on authentication failures

## API Integration

The admin portal communicates with the backend API using:

```typescript
// Example API call structure
const response = await fetch('/api/v1/organizations/{org_id}/api-keys', {
  headers: {
    'X-API-Key': 'your-admin-api-key',
    'Content-Type': 'application/json'
  }
});
```

### Error Handling

The portal includes comprehensive error handling:

- **Network Errors**: Automatic retry with user notification
- **Authentication Errors**: Redirect to login with clear messaging
- **Permission Errors**: Clear indication of insufficient permissions
- **Validation Errors**: Form validation with helpful error messages

## Development

### Project Structure

```
app/
├── admin/                    # Admin portal pages
│   ├── layout.tsx           # Admin layout with navigation
│   ├── page.tsx             # Dashboard
│   ├── api-keys/            # API key management
│   ├── organizations/       # Organization management
│   ├── analytics/           # Analytics dashboard
│   └── settings/            # User preferences
├── lib/
│   └── api-client.ts        # API communication utilities
└── globals.css              # Global styles
```

### Adding New Features

1. **Create new admin pages** in `app/admin/[feature]/page.tsx`
2. **Add navigation items** in `app/admin/layout.tsx`
3. **Implement API calls** using the `apiClient` utility
4. **Handle authentication** and permissions appropriately

### Styling Guidelines

- Use Tailwind CSS for consistent styling
- Support both light and dark themes
- Ensure responsive design for mobile devices
- Follow accessibility best practices

## Troubleshooting

### Cannot Access Admin Portal

**Symptoms**: "Please authenticate first" message

**Solutions**:
1. Verify your API key has admin permissions
2. Check that the organization ID is correct
3. Ensure the backend API is running
4. Clear browser localStorage and try again

### API Calls Failing

**Symptoms**: Error messages when performing actions

**Solutions**:
1. Check browser network tab for failed requests
2. Verify API key is still valid
3. Check backend logs for server errors
4. Ensure CORS is properly configured

### Slow Loading

**Symptoms**: Portal takes long to load

**Solutions**:
1. Check network connectivity
2. Clear browser cache
3. Verify backend API performance
4. Check for large data sets being loaded

### Permission Denied

**Symptoms**: Actions blocked due to permissions

**Solutions**:
1. Verify API key has required permissions
2. Check if you're using the correct organization ID
3. Contact administrator for permission updates

## Production Deployment

### Build Process

```bash
# Build the Next.js application
npm run build

# Start production server
npm run start
```

### Environment Variables

Set these environment variables in production:

```env
# API Backend URL
NEXT_PUBLIC_API_URL=https://api.yourdomain.com

# Admin Portal Configuration
NEXT_PUBLIC_ADMIN_TITLE="Your Company Admin Portal"
```

### Security Considerations

1. **HTTPS Only**: Always serve over HTTPS in production
2. **API Key Security**: Never log or expose API keys
3. **Rate Limiting**: Implement rate limiting on admin endpoints
4. **Audit Logging**: Log all administrative actions
5. **Session Management**: Implement proper session timeouts

### Performance Optimization

1. **Code Splitting**: Next.js automatically splits code
2. **Image Optimization**: Use Next.js Image component
3. **Caching**: Implement appropriate caching strategies
4. **CDN**: Serve static assets from a CDN

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Contributing

When contributing to the admin portal:

1. Follow the existing code structure and patterns
2. Ensure responsive design works on all screen sizes
3. Test with both light and dark themes
4. Add appropriate error handling
5. Update this documentation for new features

## API Reference

For detailed API documentation, see the main [API Documentation](../docs/api-reference.md).

## Support

For issues with the admin portal:

1. Check this troubleshooting guide
2. Review browser console for errors
3. Check backend API logs
4. Create an issue with detailed reproduction steps

---

The admin portal provides a user-friendly interface for managing your API ecosystem, with powerful analytics and monitoring capabilities to help you maintain and optimize your API usage.