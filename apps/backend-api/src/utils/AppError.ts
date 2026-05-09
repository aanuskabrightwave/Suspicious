export class AppError extends Error {
  public statusCode: number;
  public isOperational: boolean;

  constructor(statusCode: number, message: string, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    // Identifies whether the error is a known operational error (e.g. 404, validation) 
    // vs an unknown programming error (e.g. database disconnect)
    this.isOperational = isOperational;
    
    // Set the prototype explicitly to ensure instanceof works correctly in TypeScript
    Object.setPrototypeOf(this, new.target.prototype);

    // Capture the stack trace, excluding the constructor call from it
    Error.captureStackTrace(this, this.constructor);
  }
}
