const swaggerJSDoc = require("swagger-jsdoc");

const swaggerDefinition = {
  openapi: "3.1.0",
  info: {
    title: "My API",
    version: "1.0.0",
    description: "A simple API for managing users and referrals",
  },
  servers: [
    {
      url: "http://localhost:5000",
      description: "Local server",
    },
  ],
};

const options = {
  swaggerDefinition,
  apis: ["./server.js"],
};

const swaggerSpec = swaggerJSDoc(options);

module.exports = swaggerSpec;
