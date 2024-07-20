export const {
  PORT = 8001,
  SECRET_ACCESS_TOKEN = 'secret',
  EXP_TIME_ACCESS_TOKEN = '10m',
  EXP_TIME_ACCESS_TOKEN_MS = 600000,
  SECRET_REFRESH_TOKEN = 'secret2',
  EXP_TIME_REFRESH_TOKEN = '7d',
  EXP_TIME_REFRESH_TOKEN_MS = 604800000,
  FRONT_END_URL = 'http://localhost:8080',
} = process.env;
