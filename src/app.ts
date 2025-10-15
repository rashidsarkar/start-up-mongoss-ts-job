import express, { Application, Request, Response } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import router from './app/routes';

import notFound from './app/middlewares/notFound';
import globalErrorHandler from './app/middlewares/globalErrorhandler';

const app: Application = express();

// parsers
app.use(express.json());
app.use(cors());
app.use(cookieParser());

app.use('/api/v1/', router);

//Not Found

app.get('/', (req: Request, res: Response) => {
  res.send('Hello World! From Blog with build');
});
app.use(globalErrorHandler);

app.use(notFound);
export default app;
