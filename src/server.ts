import { Server } from 'http';
import mongoose from 'mongoose';
import config from './app/config';
import app from './app';
let server: Server;

async function main() {
  try {
    console.log('Attempting to connect to the database...');
    await mongoose.connect(config.database_url as string);
    console.log('Database connection established successfully.');

    server = app.listen(config.port, () => {
      console.log(`App listening on port ${config.port}`);
    });
  } catch (error) {
    console.error('Error connecting to the database:', error);
  }
}

main();
process.on('unhandledRejection', (err) => {
  console.log(` unhandledRejection is Detected , process exit`);
  console.log(err);
  if (server) {
    server.close(() => {
      process.exit(1);
    });
  }
  process.exit(1);
});
process.on('uncaughtException', () => {
  console.log(` uncaughtException is Detected , process exit`);
  process.exit(1);
});
