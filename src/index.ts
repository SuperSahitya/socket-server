import express, { Express, NextFunction, Request, Response } from "express";
import dotenv from "dotenv";
import { createServer } from "http";
import { Server } from "socket.io";
import cors from "cors";
import mongoose, { ObjectId, Schema } from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import * as cookie from "cookie";
import cookieParser from "cookie-parser";

dotenv.config();

declare module "socket.io" {
  interface Socket {
    _id: ObjectId;
    userName: string;
  }
}

declare global {
  namespace Express {
    interface Request {
      user: User;
    }
  }
}

type ActionQuery = "send-request" | "accept-request" | "decline-request";

async function connectToDatabase() {
  mongoose
    .connect(process.env.MONGODB_URI!)
    .then(() => console.log("Connected To Database Successfully."))
    .catch((e) => console.error(e));
}

connectToDatabase();

const userSchema = new Schema({
  email: { type: String, required: true, unique: true },
  name: { type: String },
  userName: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const mappingSchema = new Schema({
  userName: { type: String, required: true, unique: true },
  socketId: { type: String, required: true, unique: true },
});

const friendSchema = new Schema({
  user1: { type: String, required: true },
  user2: { type: String, required: true },
  status: {
    type: String,
    enum: ["pending", "accepted", "declined"],
    default: "pending",
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const messageSchema = new Schema({
  senderId: { type: String, required: true },
  receiverId: { type: String, required: true },
  content: { type: String, required: true },
  isDelivered: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

interface UserInput {
  email?: string;
  name?: string;
  userName?: string;
  password?: string;
}

interface User {
  _id: string;
  email: string;
  name: string;
  userName: string;
  password: string;
  createdAt: Date;
  updatedAt: Date;
}

interface Message {
  _id?: ObjectId;
  senderId: string;
  receiverId: string;
  content: string;
  isDelivered?: true;
  createdAt?: Date;
}

interface Payload {
  _id: ObjectId;
  userName: string;
}

const users = mongoose.model("users", userSchema);
const messages = mongoose.model("messages", messageSchema);
const mappings = mongoose.model("mappings", mappingSchema);
const friends = mongoose.model("friends", friendSchema);

const app: Express = express();
app.use(
  cors({
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.use(express.json());

const httpServer = createServer(app);

const io = new Server(httpServer, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  },
});

app.use(cookieParser());

io.use((socket, next) => {
  const cookiesString = socket.handshake.headers.cookie;
  // console.log("cookiesString: ", cookiesString);
  if (!cookiesString) {
    console.log("Unauthorized Access Prohibited");
    return next(new Error("Unauthorized Access Prohibited"));
  }

  const cookies = cookie.parse(cookiesString);
  const token = cookies.token;
  // console.log("token: ", token);
  if (!token) {
    console.log("Unauthorized Access Prohibited");
    return next(new Error("Unauthorized Access Prohibited"));
  }

  try {
    const payload: Payload = jwt.verify(
      token,
      process.env.JWT_SECRET!
    ) as Payload;
    const { _id, userName } = payload;
    socket._id = _id;
    socket.userName = userName;

    const user = users.findOne({
      userName: userName,
      _id: _id,
    });

    // console.log("user: ", user);
    if (!user) {
      console.log("Unauthorized Access Prohibited");
      return next(new Error("Unauthorized Access Prohibited"));
    }
    next();
  } catch (err) {
    console.log("Invalid token");
    return next(new Error("Invalid token"));
  }
});

io.on("connection", async (socket) => {
  console.log("🔥: A user connected", socket.userName);

  const idMappings = await mappings.findOneAndUpdate(
    { userName: socket.userName },
    { socketId: socket.id },
    { upsert: true }
  );

  // console.log("idMappings", idMappings);

  socket.on(
    "private-message",
    async (data: { receiverId: string; content: string }, callback) => {
      try {
        const { receiverId, content } = data;
        console.log("Received message for room: ", data);

        const relation = await friends.findOne({
          $or: [
            { user1: socket.userName, user2: receiverId, status: "accepted" },
            { user2: socket.userName, user1: receiverId, status: "accepted" },
          ],
        });

        if (!relation) {
          console.error(`You are not friends with ${receiverId}`);
          callback(`You are not friends with ${receiverId}`);
          return;
        }

        const message = await messages.create({
          senderId: socket.userName,
          receiverId: receiverId,
          content: content,
        });

        const receiverMapping = await mappings.findOne({
          userName: receiverId,
        });

        if (!receiverMapping) {
          console.error("No Receiver Found");
          return;
        }

        const receiverSocketId = receiverMapping?.socketId;
        io.to(receiverSocketId).emit("private-message", message);
        if (callback)
          callback(
            null,
            `Message received by the server from ${socket.userName}`
          );
      } catch (error) {
        console.error("Internal Socket Error: ", error);
      }
    }
  );

  socket.on("join-room", (room: string) => {
    console.log("Following room joined ", room, " by user ", socket.userName);
    socket.join(room);
  });

  socket.on("disconnect", () => {
    console.log("🔥: A user disconnected");
  });
});

httpServer.listen(5000, () => {
  console.log("Server running at http://localhost:5000");
});

async function authenticate(req: Request, res: Response, next: NextFunction) {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).send("No Token Found");
  }

  try {
    const payload: Payload = jwt.verify(
      token,
      process.env.JWT_SECRET!
    ) as Payload;

    const { _id, userName } = payload;

    const user: User | null = await users.findOne({
      userName: userName,
    });

    if (!user) {
      return res.status(400).send("Username or Password incorrect");
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("An Error Occured : ", error);
    return res.status(500).send("Internal Server Error");
  }
}

app.get("/", (req: Request, res: Response) => {
  console.log("Request Received");
  res.status(200).send({ online: "true" });
});

app.post("/register", async (req: Request, res: Response) => {
  try {
    const body: UserInput = req.body;
    if (!body) {
      return res.status(400).send("No Registration Details found.");
    }

    const alreadyExistingUser = await users.findOne({
      $or: [{ email: body.email }, { userName: body.userName }],
    });

    if (alreadyExistingUser) {
      return res.status(400).send("User Already Exists.");
    }

    const hashedPassword = await bcrypt.hash(body.password!, 10);
    const user = await users.create({
      email: body.email,
      name: body.name,
      userName: body.userName,
      password: hashedPassword,
    });
    const token = jwt.sign(
      { _id: user._id, userName: user.userName },
      process.env.JWT_SECRET!,
      {
        expiresIn: "10h",
      }
    );
    res.cookie("token", token, {
      httpOnly: true,
      // secure: true,
      maxAge: 36000000,
    });
    return res
      .status(200)
      .send({ userName: user.userName, email: user.email, name: user.name });
  } catch (error) {
    console.error("An Error Occured : ", error);
    return res.status(500).send("Internal Server Error");
  }
});

app.post("/login", async (req: Request, res: Response) => {
  try {
    connectToDatabase();
    const body: UserInput = req.body;
    if (!body) {
      return res.status(400).send("No User Data sent.");
    }
    const user: any = await users
      .findOne({
        userName: body.userName,
      })
      .catch((e) => {
        console.log(e);
      });

    if (!user) {
      return res.status(400).send("Username or Password incorrect");
    }
    const isPasswordMatch = await bcrypt.compare(body.password!, user.password);
    if (!isPasswordMatch) {
      return res.status(400).send("Password is incorrect");
    }
    const token = jwt.sign(
      { _id: user._id, userName: user.userName },
      process.env.JWT_SECRET!,
      {
        expiresIn: "10h",
      }
    );
    res.cookie("token", token, {
      httpOnly: true,
      // secure: true,
      maxAge: 36000000,
    });
    return res
      .status(200)
      .send({ userName: user.userName, email: user.email, name: user.name });
  } catch (error) {
    console.error("An Error Occured : ", error);
    return res.status(500).send("Internal Server Error");
  }
});

app.post("/message", async (req: Request, res: Response) => {
  try {
    const body: Message = req.body;
    if (!body) {
      return res.status(400).send("No Message found.");
    }
    if (!body.senderId || !body.receiverId || !body.content) {
      return res.status(400).send("No Message, Sender, Content found.");
    }

    const token = req.cookies.token;

    if (!token) {
      return res.status(400).send("Unauthorized Access Prohibited");
    }

    const payload: Payload = jwt.verify(
      token,
      process.env.JWT_SECRET!
    ) as Payload;
    const { _id, userName: userNameFromToken } = payload;

    const sender: User | null = await users.findOne({
      userName: body.senderId,
    });

    const receiver: User | null = await users.findOne({
      userName: body.senderId,
    });

    if (!sender || !receiver) {
      return res.status(400).send("Sender or Receiver not found");
    }

    if (userNameFromToken === sender!.userName) {
      messages.create({
        senderId: sender!.userName,
        receiverId: receiver!.userName,
        content: body.content,
      });
    }
  } catch (error) {
    console.error("An Error Occured : ", error);
    return res.status(500).send("Internal Server Error");
  }
});

app.get("/auth/status", async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).send("No Token Found");
  }

  const payload: Payload = jwt.verify(
    token,
    process.env.JWT_SECRET!
  ) as Payload;

  const { _id, userName } = payload;

  const user: User | null = await users.findOne({
    userName: userName,
  });

  if (!user) {
    return res.status(400).send("Username or Password incorrect");
  }

  return res
    .status(200)
    .send({ userName: user.userName, email: user.email, name: user.name });
});

app.get("/messages/:receiverId", async (req: Request, res: Response) => {
  const token = req.cookies.token;
  const { receiverId } = req.params;

  if (!token) {
    return res.status(401).send({ authenticated: false });
  }

  const payload: Payload = jwt.verify(
    token,
    process.env.JWT_SECRET!
  ) as Payload;

  const { _id, userName } = payload;

  const user: User | null = await users.findOne({
    userName: userName,
    _id: _id,
  });

  if (!user) {
    return res.status(400).send("Username or Password incorrect");
  }

  const messageFromReceiver = await messages.find({
    $or: [
      { senderId: userName, receiverId: receiverId },
      { senderId: receiverId, receiverId: userName },
    ],
  });

  res.status(200).send(messageFromReceiver);
});

app.get("/logout", (req: Request, res: Response) => {
  res.clearCookie("token", { httpOnly: true });
  res.status(200).send("User logged out");
});

app.post("/request/:receiverId", async (req: Request, res: Response) => {
  const token = req.cookies.token;
  const { receiverId } = req.params;
  const query = req.query;

  if (!query) {
    return res.status(400).send("Please specify query.");
  }

  const action: ActionQuery = query.action as ActionQuery;

  if (!action) {
    return res.status(400).send("Please specify action query.");
  }

  if (!token) {
    return res.status(401).send({ authenticated: false });
  }

  const payload: Payload = jwt.verify(
    token,
    process.env.JWT_SECRET!
  ) as Payload;

  const { _id, userName } = payload;

  const user: User | null = await users.findOne({
    userName: userName,
    _id: _id,
  });

  if (!user) {
    return res.status(400).send("Invalid User");
  }

  if (receiverId == userName) {
    return res.status(400).send("Cannot send request to self.");
  }

  const receiver: User | null = await users.findOne({ userName: receiverId });

  if (!receiver) {
    return res.status(400).send("Receiver does not exist");
  }

  const friendRelation = await friends.findOne({
    $or: [
      { user1: userName, user2: receiverId },
      { user2: userName, user1: receiverId },
    ],
  });

  if (action == "send-request") {
    if (friendRelation) {
      if (friendRelation.status == "accepted") {
        return res
          .status(400)
          .send(`You are already friends with ${receiverId}`);
      } else {
        return res
          .status(400)
          .send(`You have already sent a friend request to ${receiverId}`);
      }
    }

    await friends.create({
      user1: userName,
      user2: receiverId,
    });

    return res.status(201).send(`Friend requets sent to ${receiverId}`);
  } else if (action == "accept-request") {
    if (friendRelation) {
      if (friendRelation.status == "accepted") {
        return res
          .status(400)
          .send(`You are already friends with ${receiverId}`);
      } else if (friendRelation.status == "declined") {
        return res
          .status(400)
          .send(`You have a friend request from ${receiverId}`);
      }
    }
    await friends.updateOne(
      { user2: userName, user1: receiverId },
      { status: "accepted" }
    );

    return res.status(201).send(`Friend requets accepted to ${receiverId}`);
  } else if (action == "decline-request") {
    if (friendRelation) {
      if (friendRelation.status == "accepted") {
        return res
          .status(400)
          .send(`You are already friends with ${receiverId}`);
      } else if (friendRelation.status == "declined") {
        return res
          .status(400)
          .send(`You have declined request from ${receiverId}`);
      }
    }
    await friends.updateOne(
      { user2: userName, user1: receiverId },
      { status: "declined" }
    );

    return res.status(201).send(`Friend requets declined from ${receiverId}`);
  } else {
    return res.status(201).send(`Invalid Action ${action}`);
  }
});

app.get("/friends", async (req: Request, res: Response) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).send({ authenticated: false });
  }

  const payload: Payload = jwt.verify(
    token,
    process.env.JWT_SECRET!
  ) as Payload;

  const { _id, userName } = payload;

  const user: User | null = await users.findOne({
    userName: userName,
    _id: _id,
  });

  if (!user) {
    return res.status(400).send("Invalid User");
  }

  const friendsList = await friends.find({
    $or: [{ user1: userName }, { user2: userName }],
  });

  if (friendsList) {
    res.status(200).send(friendsList);
  } else {
    res.status(200).send({ message: "No Friends Found" });
  }
});
