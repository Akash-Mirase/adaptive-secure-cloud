// An error we THROW ON PURPOSE (wrong password, forbidden, not found...).
// Its message is safe to show to the client. Any other error (a bug, a DB
// crash) is unexpected, so the error handler hides its details.
export default class AppError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.name = 'AppError';
    this.status = status;
    this.isOperational = true;
  }
}