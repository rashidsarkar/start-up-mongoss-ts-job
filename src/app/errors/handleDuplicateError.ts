/* eslint-disable @typescript-eslint/no-explicit-any */
import { TErrorSources, TGenericErrorResponse } from '../interface/error';

const handleDuplicateError = (err: any): TGenericErrorResponse => {
  const field = Object.keys(err.keyValue)[0];
  const value = err.keyValue[field];
  // console.log(err);

  const errorSources: TErrorSources = [
    {
      path: field,
      message: `${value} is already exists`,
    },
  ];

  const statusCode = 409;
  return {
    statusCode,
    message: `Duplicate field value: ${field}`,
    errorSources,
  };
};

export default handleDuplicateError;
