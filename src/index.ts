import express, { Express, Request, Response } from "express";
import dotenv from "dotenv";
import { createServer } from "http";
import { Server } from "socket.io";
import cors from "cors";

dotenv.config();

const app: Express = express();
app.use(
  cors({
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

const httpServer = createServer(app);

const io = new Server(httpServer, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
  },
});

io.on("connection", (socket) => {
  console.log("🔥: A user connected");
  const id = socket.id;
  console.log(id);

  socket.on("message", (message: string, callback) => {
    console.log("Received message: ", message);
    io.emit("message", message);
    if (callback) callback(`Message received by the server from ${id}`);
  });

  socket.on(
    "message-room",
    (data: { room: string; message: string }, callback) => {
      const { room, message } = data;
      console.log("Received message for room: ", data);
      io.to(room).emit("message-room", data);
      if (callback) callback(`Message received by the server from ${id}`);
    }
  );

  socket.on("join-room", (room: string) => {
    console.log("Following room joined ", room, " by user ", id);
    socket.join(room);
  });

  socket.on("disconnect", () => {
    console.log("🔥: A user disconnected");
  });
});

httpServer.listen(5000, () => {
  console.log("Server running at http://localhost:5000");
});
