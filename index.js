const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const bcrypt = require("bcrypt");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 5000;

/*
--------------------------
Middleware
--------------------------
*/
app.use(helmet());

app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  }),
);
app.use(express.json());
app.use(cookieParser());

/*
---------------------------
Rate limit for login 
---------------------------
*/

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many login attempts. Try again later",
});

/*
----------------------------------
MongoDB Atlas Connection URI
----------------------------------
*/

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.v0ym3.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

/*
-------------------------
Token Generator
-------------------------
*/

const generateToken = (user) => {
  const accessToken = jwt.sign(
    {
      id: user._id,
      email: user.email,
    },
    process.env.ACCESS_SECRET,
    { expiresIn: "15m" },
  );

  const refreshToken = jwt.sign({ id: user._id }, process.env.REFRESH_SECRET, {
    expiresIn: "7d",
  });

  return { accessToken, refreshToken };
};

/*
-------------------------
Verify Access Token
-------------------------
*/

const verifyAccessToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) return res.sendStatus(401);

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.ACCESS_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") return res.sendStatus(401);
      return res.sendStatus(403);
    }
    req.decoded = decoded;
    next();
  });
};

/*
-------------------------
Verify Admin
-------------------------
*/

const verifyAdmin = async (req, res, next) => {
  try {
    const email = req.decoded?.email;

    if (!email) {
      return res.status(401).send({ message: "Unauthorized access" });
    }

    const user = await userCollection.findOne({ email });

    if (!user) {
      return res.status(404).send({ message: "User not found" });
    }

    if (user.role !== "admin") {
      return res.status(403).json({ message: "Forbidden: Admin only" });
    }

    next();
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
};

async function run() {
  try {
    // Connect the client to the server
    await client.connect();

    // Define your Database and Collection
    const db = client.db("cineTradeDB");
    const movieCollection = db.collection("movies");
    const usersCollection = db.collection("users");
    const refreshTokenCollection = db.collection("refreshTokens");
    const partnerApplicationsCollection = db.collection("partnerApplications");

    /*
    -------------------------
    POST: Register API
    -------------------------
    */

    app.post(
      "/register",
      [
        body("fullName").notEmpty(),
        body("email").isEmail(),
        body("password").isLength({ min: 8 }),
      ],
      async (req, res) => {
        try {
          const errors = validationResult(req);

          if (!errors.isEmpty()) {
            return res.status(400).json(errors);
          }

          const { fullName, email, password } = req.body;

          // check if user exists
          const existingUser = await usersCollection.findOne({ email });

          if (existingUser) {
            return res.status(400).json({ message: "Email is already exists" });
          }

          // Hash Password
          const hashedPassword = await bcrypt.hash(password, 10);

          // Insert User
          const result = await usersCollection.insertOne({
            fullName,
            email,
            password: hashedPassword,
            role: "user",
            createdAt: new Date(),
          });

          res.status(201).json({
            message: "User registered successfully",
            userId: result.insertedId,
          });
        } catch (err) {
          console.error(err);
          res.status(500).json({ message: "Server error" });
        }
      },
    );

    /*
    -------------------------
    Login API
    -------------------------
    */

    app.post("/login", loginLimiter, async (req, res) => {
      try {
        const { email, password } = req.body;

        const user = await usersCollection.findOne({ email });

        if (!user) {
          return res.status(401).json({ message: "Invalid credentials" });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
          return res.status(401).json({ message: "Invalid credentials" });
        }

        const { accessToken, refreshToken } = generateToken(user);

        await refreshTokenCollection.insertOne({
          token: refreshToken,
          userId: user._id,
          createdAt: new Date(),
        });

        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: false,
          sameSite: "Lax",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.json({
          accessToken,
          user: {
            id: user._id,
            fullName: user.fullName,
            email: user.email,
            role: user.role,
            profilePic: user.profilePic || null,
          },
        });
      } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "Internal Server Error" });
      }
    });

    /*
    -------------------------
    Refresh Token API
    -------------------------
    */

    app.post("/refresh", async (req, res) => {
      try {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) return res.sendStatus(401);

        // 1. Find the token first
        const tokenExists = await refreshTokenCollection.findOne({
          token: refreshToken,
        });

        if (!tokenExists) {
          console.log("Refresh token not found in database");
          return res.sendStatus(403);
        }

        // 2. Verify and decode
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);

        // 3. convert string ID to MongoDB ObjectId for the lookup
        const user = await usersCollection.findOne({
          _id: new ObjectId(decoded.id),
        });

        if (!user) {
          console.log("User not found during refresh lookup");
          return res.sendStatus(403);
        }

        // 4. Token Rotation: Delete old, add new
        await refreshTokenCollection.deleteOne({ token: refreshToken });

        const { accessToken, refreshToken: newRefreshToken } =
          generateToken(user);

        await refreshTokenCollection.insertOne({
          token: newRefreshToken,
          userId: user._id,
        });

        // 5. Set the cookie
        res.cookie("refreshToken", newRefreshToken, {
          httpOnly: true,
          secure: false,
          sameSite: "Lax",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        // 6. Send the data
        res.json({
          accessToken,
          user: {
            id: user._id,
            fullName: user.fullName,
            email: user.email,
            role: user.role,
            profilePic: user.profilePic || null,
          },
        });
      } catch (err) {
        console.error("Refresh Route Error:", err.message);
        res.sendStatus(403);
      }
    });

    /*
    -------------------------
    Logout API
    -------------------------
    */

    app.post("/logout", async (req, res) => {
      try {
        const refreshToken = req.cookies.refreshToken;

        // 1. Remove the specific token from the Database
        if (refreshToken) {
          await refreshTokenCollection.deleteOne({ token: refreshToken });
        }

        // 2. Clear the cookie from the browser
        res.clearCookie("refreshToken", {
          httpOnly: true,
          secure: false,
          sameSite: "Lax",
        });

        res.status(200).json({ message: "Logged out successfully" });
      } catch (error) {
        console.error("Logout Error:", error);
        res.status(500).json({ message: "Internal Server Error" });
      }
    });


    /*
    -------------------------
    GET: All users API
    -------------------------
    */

    app.get("/users", verifyAccessToken, verifyAdmin, async (req, res) => {
      try {
        const users = await usersCollection.find().toArray();

        res.status(200).json({
          success: true,
          data: users,
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: "Failed to fetch users",
        });
      }
    });

    /*
    -------------------------
    GET: All Movies by Genres API
    -------------------------
    */

    app.get("/movies", async (req, res) => {
      try {
        const { genre, sort, rating, language, year } = req.query;

        let query = {};
        let sortOption = {};

        if (language) {
          query.language = { $regex: new RegExp(`^${language}$`, "i") };
        }

        if (year) {
          query.release_year = parseInt(year);
        }

        if (rating === "high") {
          query.rating = { $gte: 7 };
        } else if (rating === "low") {
          query.rating = { $lt: 7 };
        }

        if (genre) {
          query.genres = genre;
        }

        switch (sort) {
          case "price_asc":
            sortOption = { price: 1 };
            break;
          case "price_desc":
            sortOption = { price: -1 };
            break;
          case "rating_desc":
            sortOption = { rating: -1 };
            break;
          case "rating_asc":
            sortOption = { rating: 1 };
            break;
        }

        const result = await movieCollection
          .find(query)
          .sort(sortOption)
          .toArray();

        res.json(result);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch movies" });
      }
    });

    /*
    -------------------------
    GET: Movie Coming Soon API
    -------------------------
    */

    app.get("/movies/coming-soon", async (req, res) => {
      try {
        const query = { release_status: "upcoming" };

        const result = await movieCollection
          .find(query)
          .sort({ created_at: -1 })
          .limit(5)
          .toArray();

        res.status(200).json(result);
      } catch (error) {
        res
          .status(500)
          .json({ message: "Error fetching upcoming movies", error });
      }
    });

    /*
    -------------------------
    GET: Movie Genres API
    -------------------------
    */

    app.get("/movies/genres", async (req, res) => {
      try {
        const uniqueGenres = await movieCollection
          .aggregate([
            { $unwind: "$genres" }, //flatten the genres array
            { $group: { _id: "$genres" } }, // group by each genre
            { $sort: { _id: 1 } }, // sort alphabetically
            { $project: { _id: 0, genre: "$_id" } },
          ])
          .toArray();

        const genreList = uniqueGenres.map((g) => g.genre);

        res.json(genreList);
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error fetching genres" });
      }
    });

    /*
    -------------------------
    GET: Movie Popular on cineTrade API
    -------------------------
    */

    app.get("/movies/popular", async (req, res) => {
      try {
        const result = await movieCollection
          .find({})
          .sort({ views: -1 })
          .limit(10)
          .toArray();

        res.json(result);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch popular movies" });
      }
    });

    /*
    -------------------------
    GET: Movie New Release on cineTrade API
    -------------------------
    */

    app.get("/movies/new-releases", async (req, res) => {
      try {
        const currentYear = new Date().getFullYear();

        const newReleases = await movieCollection
          .find({
            release_status: "released",
            release_year: currentYear,
          })
          .sort({ created_at: -1 })
          .limit(10)
          .toArray();

        res.json(newReleases);
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Failed to fetch new release movies" });
      }
    });

    /*
    -------------------------
    POST: Partner Application API
    -------------------------
    */

    app.post("/partner/apply", verifyAccessToken, async (req, res) => {
      try {
        const { fullName, reason } = req.body;

        // get user from token
        const userId = req.decoded?.id;
        const email = req.decoded?.email;

        if (!userId || !email) {
          return res.status(401).json({ message: "Unauthorized" });
        }

        if (!fullName || !reason) {
          return res.status(400).json({ message: "All fields are required" });
        }

        // prevent duplicate application
        const existing = await partnerApplicationsCollection.findOne({
          userId,
          status: { $in: ["pending", "approved"] },
        });

        if (existing) {
          return res.status(400).json({
            message: "You already applied or are approved",
          });
        }

        const application = {
          userId,
          email,
          fullName,
          reason,
          status: "pending",
          paymentStatus: "unpaid",
          createdAt: new Date(),
        };

        await partnerApplicationsCollection.insertOne(application);

        res.status(201).json({
          message: "Application submitted successfully",
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
      }
    });

    /*
    -------------------------
    GET: Partner Application API
    -------------------------
    */

    app.get("/partner/my-application", verifyAccessToken, async (req, res) => {
      try {
        const userId = req.decoded?.id;

        if (!userId) {
          return res.status(401).json({ message: "Unauthorized" });
        }

        const application = await partnerApplicationsCollection.findOne({
          userId,
        });

        if (!application) {
          return res.status(200).json(null);
        }

        res.status(200).json(application);
      } catch (error) {
        console.error("Error fetching application:", error);
        res.status(500).json({ message: "Server error" });
      }
    });

    /*
    -------------------------
    GET: Single Movies API
    -------------------------
    */

    app.get("/movies/:id", async (req, res) => {
      try {
        const movieId = req.params.id;

        if (!ObjectId.isValid(movieId)) {
          return res.status(400).json({ message: "Invalid movie ID" });
        }

        const movie = await movieCollection.findOne({
          _id: new ObjectId(movieId),
        });

        if (!movie) {
          return res.status(404).json({ message: "Movie not found" });
        }

        res.status(200).json(movie);
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error" });
      }
    });

    console.log("Successfully connected to MongoDB Atlas!");
  } catch (err) {
    console.error("Failed to connect to MongoDB", err);
  }
}

// Start the MongoDB connection
run().catch(console.dir);

// Root Route
app.get("/", (req, res) => {
  res.send("CineTrade Server is running");
});

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
