import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { PORT } from 'config';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());
  await app.listen(PORT);
  console.log('Server is running on port', PORT);
}
bootstrap();