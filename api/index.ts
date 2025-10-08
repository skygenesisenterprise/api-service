import express from 'express';
import authRoutes from './routes/auth.Routes';
// import protectedRoutes from './routes/protected.Routes';
import logger from './utils/logger';

const app = express();
const port = 3001; // Changez le port à 3001

app.use(express.json()); // Pour parser les requêtes JSON

app.use('/api', authRoutes);
// app.use('/api', protectedRoutes);

app.listen(port, () => {
  logger.info(`Server is running on http://localhost:${port}`);
});

export default app;