import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { FRONT_END_URL, PORT } from 'config';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    credentials: true,
    origin: FRONT_END_URL,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    preflightContinue: false,
    optionsSuccessStatus: 204,
  });

  app.use(cookieParser());
  await app.listen(PORT);
  console.log('Server is running on port', PORT);
}
bootstrap();
