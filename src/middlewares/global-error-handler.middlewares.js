const global_error_handler = async (err, req, res, next) => {
  const message = err.message || "something went wrong globally";
  const statusCode = err.statusCode || 522;

  return res.status(statusCode).json({
    success: false,
    message,
    statusCode,
    errors: err.errors || [],
  });
};

export default global_error_handler;
