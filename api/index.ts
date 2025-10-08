import express from 'express';
import authRoutes from './routes/auth.Routes';
import logger from './utils/logger';

const app = express();
const port = 3000;

app.use(express.json());
app.use('/api', authRoutes);

app.listen(port, () => {
  logger.info(`Server is running on http://localhost:${port}`);
});

export default app;