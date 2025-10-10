import express from 'express';
import authRoutes from './routes/auth.Routes';
import messagingRoutes from './routes/messagingRoutes';
import apiKeyRoutes from './routes/apiKeyRoutes';
// import protectedRoutes from './routes/protected.Routes';
import logger from './utils/logger';

const app = express();
const port = 3001; // Changez le port à 3001

app.use(express.json()); // Pour parser les requêtes JSON

// Legacy auth routes (for backward compatibility)
app.use('/api', authRoutes);

// API Key authenticated routes
app.use('/api/v1', apiKeyRoutes);
app.use('/api/v1', messagingRoutes);

// app.use('/api', protectedRoutes);

app.listen(port, () => {
  logger.info(`Server is running on http://localhost:${port}`);
});

export default app;