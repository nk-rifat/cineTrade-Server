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

const Stripe = require("stripe");
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

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

async function run() {
  try {
    // Connect the client to the server
    // await client.connect();

    // Define your Database and Collection
    const db = client.db("cineTradeDB");
    const movieCollection = db.collection("movies");
    const usersCollection = db.collection("users");
    const refreshTokenCollection = db.collection("refreshTokens");
    const partnerApplicationsCollection = db.collection("partnerApplications");
    const paymentsCollection = db.collection("paymentCollections");

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
            status: "active",
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
        if (user.status === "banned") {
          return res
            .status(403)
            .json({ message: "This account has been suspended." });
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
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
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

        // if user banned
        if (user.status === "banned") {
          await refreshTokenCollection.deleteMany({ userId: user._id });
          return res.status(403).json({ message: "Account suspended." });
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
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
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
          const tokenDoc = await refreshTokenCollection.findOne({
            token: refreshToken,
          });

          if (tokenDoc) {
            // 2. Delete ALL tokens where userId matches this token's owner
            await refreshTokenCollection.deleteMany({
              userId: tokenDoc.userId,
            });
          }
        }

        // 2. Clear the cookie from the browser
        res.clearCookie("refreshToken", {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        });

        res.status(200).json({ message: "Logged out successfully" });
      } catch (error) {
        console.error("Logout Error:", error);
        res.status(500).json({ message: "Internal Server Error" });
      }
    });

    /*
    -------------------------
    Verify Access Token
    -------------------------
    */

    const verifyAccessToken = (req, res, next) => {
      const authHeader = req.headers.authorization;
      if (!authHeader) return res.sendStatus(401);

      const token = authHeader.split(" ")[1];

      jwt.verify(token, process.env.ACCESS_SECRET, async (err, decoded) => {
        if (err) {
          if (err.name === "TokenExpiredError")
            return res.status(401).send({ message: "Expired" });
          return res.sendStatus(403);
        }

        try {
          if (!usersCollection) {
            return res
              .status(500)
              .send({ message: "Database not initialized" });
          }

          const user = await usersCollection.findOne({
            _id: new ObjectId(decoded.id),
          });

          if (!user) {
            return res.status(404).send({ message: "User not found" });
          }

          if (user.status === "banned") {
            return res.status(403).json({ message: "Account suspended" });
          }

          req.decoded = decoded;

          next();
        } catch (error) {
          console.error("Middleware Error:", error);
          res.status(500).send("Internal Server Error");
        }
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

        const user = await usersCollection.findOne({ email });

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

    /*
    -------------------------
    Verify Partner
    -------------------------
    */

    const verifyPartner = async (req, res, next) => {
      try {
        // 1. Extract email from the decoded token
        const email = req.decoded?.email;

        if (!email) {
          return res.status(401).send({ message: "Unauthorized access" });
        }

        // 2. Fetch the user from the database
        const user = await usersCollection.findOne({ email });

        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        // 3. Verify if the role is 'partner'
        if (user.role !== "partner") {
          return res
            .status(403)
            .json({ message: "Forbidden: Partner access only" });
        }

        // 4. Proceed to the next middleware or controller
        next();
      } catch (error) {
        console.error("Error in verifyPartner middleware:", error);
        res.status(500).json({ message: "Server error" });
      }
    };

    /*
    -------------------------
    GET: All users for Admin Dashboard
    -------------------------
    */

    app.get("/admin/users", verifyAccessToken, verifyAdmin, async (req, res) => {
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
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const { genre, sort, language, year } = req.query;

        let query = { release_status: { $in: ["released", "upcoming"] } };

        let sortOption = {};

        if (language) {
          query.language = { $regex: new RegExp(`^${language}$`, "i") };
        }

        if (year) {
          query.release_year = parseInt(year);
        }

        if (genre) {
          query.genres = { $in: [genre] };
        }

        switch (sort) {
          case "price_asc":
            sortOption = { price: 1 };
            break;
          case "price_desc":
            sortOption = { price: -1 };
            break;
          default:
            sortOption = { _id: -1 };
        }
        const totalCount = await movieCollection.countDocuments(query);

        const movies = await movieCollection
          .find(query)
          .sort(sortOption)
          .skip(skip)
          .limit(limit)
          .toArray();

        res.json({
          movies,
          totalCount,
          totalPages: Math.ceil(totalCount / limit),
          currentPage: page,
        });
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch movies" });
      }
    });

    /*
    -------------------------
    GET: Search Result
    -------------------------
    */

    app.get("/search", async (req, res) => {
      try {
        let { title } = req.query;

        if (!title) {
          return res.status(200).json([]);
        }

        title = title.trim();

        if (title.length < 2) {
          return res.status(200).json([]);
        }

        const results = await movieCollection
          .find({
            title: { $regex: title, $options: "i" },
          })
          .project({
            _id: 1,
            title: 1,
            poster: 1,
            year: 1,
          })
          .limit(6)
          .toArray();

        return res.status(200).json(results);
      } catch (error) {
        console.error("Search Error:", error);
        return res.status(500).json({ message: "Internal Server Error" });
      }
    });

    /*
    -------------------------
    GET: All Movies for Admin
    -------------------------
    */

    app.get(
      "/admin/all-movies",
      verifyAccessToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const page = parseInt(req.query.page) || 1;
          const limit = parseInt(req.query.limit) || 10;
          const addedBy = req.query.addedBy;

          const skip = (page - 1) * limit;

          let query = {};

          // filter by who added movie
          if (addedBy && addedBy !== "all") {
            query.added_by = { $regex: `^${addedBy}$`, $options: "i" };
          }

          const total = await movieCollection.countDocuments(query);

          const movies = await movieCollection
            .find(query)
            .skip(skip)
            .limit(limit)
            .toArray();

          res.json({
            movies,
            total,
            currentPage: page,
            totalPages: Math.ceil(total / limit),
          });
        } catch (error) {
          res.status(500).json({ message: "Failed to fetch admin movies" });
        }
      },
    );

    /*
    -------------------------
    GET: All pending movies for Admin Approval
    -------------------------
    */

    app.get(
      "/admin/pending-movies",
      verifyAccessToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const result = await movieCollection
            .find({ release_status: "pending" })
            .toArray();

          res.status(200).json(result);
        } catch (error) {
          console.error("Error fetching pending movies:", error);
        }
      },
    );

    /*
    -------------------------
    POST: Add New Movie
    -------------------------
    */

    app.post("/add-movie", verifyAccessToken, async (req, res) => {
      try {
        const userEmail = req.decoded?.email;

        const user = await usersCollection.findOne({ email: userEmail });
        if (!user) {
          return res.status(404).json({
            success: false,
            message: "User not found",
          });
        }

        if (user?.role !== "admin" && user?.role !== "partner") {
          return res.status(403).json({
            success: false,
            message: "Forbidden: You do not have permission to add movies.",
          });
        }

        const currentYear = new Date().getFullYear();
        const inputYear = parseInt(req.body.release_year);

        const isAdmin = user.role === "admin";

        let finalStatus = isAdmin
          ? inputYear > currentYear
            ? "upcoming"
            : "released"
          : "pending";

        const newMovieData = {
          ...req.body,
          email: userEmail,
          added_by: isAdmin ? "Admin" : "Partner",
          release_status: finalStatus,
          rating: 0,
          views: 0,
          sold: 0,
          created_at: new Date().toISOString(),
        };

        const result = await movieCollection.insertOne(newMovieData);

        res.status(201).json({
          success: true,
          message: "Movie added successfully",
          data: result,
        });
      } catch (error) {
        console.error("Error adding movie:", error);
        res.status(500).json({
          success: false,
          message: "Internal Server Error",
        });
      }
    });

    /*
    -------------------------
    GET: Partner's Own Pending Movies
    -------------------------
    */

    app.get(
      "/partner/movies/pending",
      verifyAccessToken,
      verifyPartner,
      async (req, res) => {
        try {
          const userEmail = req?.decoded?.email;

          const result = await movieCollection
            .find({
              email: userEmail,
              release_status: "pending",
            })
            .sort({ created_at: -1 })
            .toArray();

          res.json(result);
        } catch (error) {
          res.status(500).json({ message: "Failed to fetch pending movies" });
        }
      },
    );

    /*
    -------------------------
    GET: Uploaded Movies by Partner
    -------------------------
    */

    app.get(
      "/partner/uploaded-movies",
      verifyAccessToken,
      verifyPartner,
      async (req, res) => {
        try {
          const email = req?.decoded?.email;

          const result = await movieCollection
            .find({ email, release_status: { $ne: "pending" } })
            .toArray();

          res.json(result);
        } catch (error) {
          console.error("Error fetching partner movies:", error);
          res.status(500).json({
            message: "Failed to get partner movies",
            error: error.message,
          });
        }
      },
    );

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
            {
              $match: {
                release_status: { $ne: "pending" },
              },
            },
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
          .sort({ views: -1, sold: -1 })
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
    POST: All purchase movies by users
    -------------------------
    */

    app.post("/movies/purchase/by-ids", verifyAccessToken, async (req, res) => {
      try {
        const { ids } = req.body;

        // validation
        if (!ids || !Array.isArray(ids)) {
          return res.status(400).json({ message: "Invalid ids array" });
        }

        // convert to ObjectId
        const objectIds = ids
          .filter((id) => ObjectId.isValid(id))
          .map((id) => new ObjectId(id));

        // fetch movies
        const movies = await movieCollection
          .find({ _id: { $in: objectIds } })
          .toArray();

        // keep original order (important)
        const sortedMovies = ids
          .map((id) => movies.find((m) => m._id.toString() === id))
          .filter(Boolean);

        res.status(200).json(sortedMovies);
      } catch (error) {
        console.error("Error fetching movies by ids:", error);
        res.status(500).json({ message: "Server error" });
      }
    });

    /*
    -------------------------
    GET: User Profile details
    -------------------------
    */

    app.get("/users/me", verifyAccessToken, async (req, res) => {
      try {
        const email = req?.decoded?.email;

        const user = await usersCollection.findOne({ email });

        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        res.json({
          id: user._id,
          fullName: user.fullName,
          email: user.email,
          role: user.role,
          profilePic: user.profilePic,
          purchasedMovies: user.purchasedMovies ?? [],
        });
      } catch (error) {
        console.error("Error", error);

        res.status(500).json({
          message: "Internal Server Error",
          error: error.message,
        });
      }
    });

    /*
    -------------------------
    GET: Admin Dashboard Summary api
    -------------------------
    */

    app.get(
      "/admin/dashboard",
      verifyAccessToken,
      verifyAdmin,
      async (req, res) => {
        try {
          // 1. GLOBAL COUNTS (Optimized simultaneous execution)
          const [totalUsers, totalPartners] = await Promise.all([
            usersCollection.countDocuments(),
            usersCollection.countDocuments({ role: "partner" }),
          ]);

          // 2. TOP PERFORMING MOVIES (Admin Uploads Only)

          const topMovies = await movieCollection
            .find({ added_by: "Admin" })
            .sort({ sold: -1 })
            .limit(5)
            .toArray();

          // 3. RECENT SALES FEED (Admin Movies & Partner Registration Fees Only)

          const recentTransactions = await paymentsCollection
            .find({
              status: "success",
              $or: [
                { type: "partner" },
                { $and: [{ type: "movie" }, { added_by: "Admin" }] },
              ],
            })
            .sort({ created_at: -1, createdAt: -1 })
            .limit(5)
            .toArray();

          // 4. FINANCIAL TOTALS (Top Dashboard Cards)
          const financialStats = await paymentsCollection
            .aggregate([
              { $match: { status: "success" } },
              {
                $group: {
                  _id: null,
                  adminSales: {
                    $sum: {
                      $cond: [
                        {
                          $and: [
                            { $eq: ["$type", "movie"] },
                            { $eq: ["$added_by", "Admin"] },
                          ],
                        },
                        { $toDouble: "$amount" },
                        0,
                      ],
                    },
                  },
                  partnerTotalSales: {
                    $sum: {
                      $cond: [
                        {
                          $and: [
                            { $eq: ["$type", "movie"] },
                            { $eq: ["$added_by", "Partner"] },
                          ],
                        },
                        { $toDouble: "$amount" },
                        0,
                      ],
                    },
                  },
                  regFees: {
                    $sum: {
                      $cond: [
                        { $eq: ["$type", "partner"] },
                        { $toDouble: "$amount" },
                        0,
                      ],
                    },
                  },
                },
              },
            ])
            .toArray();

          const f = financialStats[0] || {
            adminSales: 0,
            partnerTotalSales: 0,
            regFees: 0,
          };
          const partnerProfitCut = f.partnerTotalSales * 0.2;
          const totalNetEarnings = f.adminSales + partnerProfitCut + f.regFees;

          // 5. MONTHLY NET INCOME ANALYTICS (The Profit Chart)

          const salesRaw = await paymentsCollection
            .aggregate([
              { $match: { status: "success" } },
              {
                $group: {
                  _id: {
                    $month: {
                      $toDate: { $ifNull: ["$created_at", "$createdAt"] },
                    },
                  },
                  total: {
                    $sum: {
                      $cond: [
                        {
                          $or: [
                            { $eq: ["$added_by", "Admin"] },
                            { $eq: ["$type", "partner"] },
                          ],
                        },
                        { $toDouble: { $ifNull: ["$amount", 0] } }, // 100% share
                        {
                          $multiply: [
                            { $toDouble: { $ifNull: ["$amount", 0] } },
                            0.2,
                          ],
                        }, // 20% share
                      ],
                    },
                  },
                },
              },
              { $sort: { _id: 1 } },
            ])
            .toArray();

          // 6. INVENTORY GROWTH ANALYTICS (Content Expansion Chart)
          const moviesRaw = await movieCollection
            .aggregate([
              {
                $group: {
                  _id: {
                    $month: {
                      $toDate: { $ifNull: ["$created_at", "$createdAt"] },
                    },
                  },
                  count: { $sum: 1 },
                },
              },
              { $sort: { _id: 1 } },
            ])
            .toArray();

          // 7. CHART FORMATTER HELPER (Ensures Jan-Dec display)
          const formatChartData = (raw, isCount = false) => {
            const months = [
              "Jan",
              "Feb",
              "Mar",
              "Apr",
              "May",
              "Jun",
              "Jul",
              "Aug",
              "Sep",
              "Oct",
              "Nov",
              "Dec",
            ];
            return months.map((name, index) => {
              const found = raw.find((item) => item._id === index + 1);
              return {
                month: name,
                value: found ? (isCount ? found.count : found.total) : 0,
              };
            });
          };

          // 8. FINAL JSON RESPONSE
          res.json({
            stats: {
              totalUsers,
              totalPartners,
              adminMovieSales: f.adminSales,
              partnerProfit: partnerProfitCut,
              partnerFees: f.regFees,
              totalEarnings: totalNetEarnings,
            },
            analytics: {
              sales: formatChartData(salesRaw),
              movies: formatChartData(moviesRaw, true),
            },
            topMovies,
            recentTransactions,
          });
        } catch (err) {
          console.error("Dashboard API Error:", err);
          res.status(500).json({
            error: "Failed to generate dashboard data",
            message: err.message,
          });
        }
      },
    );

    /*
    -------------------------
    GET: Partner Dashboard summary api
    -------------------------
    */

    app.get(
      "/partner/dashboard",
      verifyAccessToken,
      verifyPartner,
      async (req, res) => {
        try {
          const email = req?.decoded?.email;

          // 1. Core Movie Stats
          const movieStats = await movieCollection
            .aggregate([
              { $match: { email: email } },
              {
                $group: {
                  _id: null,
                  totalMovies: { $sum: 1 },
                  approved: {
                    $sum: {
                      $cond: [
                        { $in: ["$release_status", ["released", "upcoming"]] },
                        1,
                        0,
                      ],
                    },
                  },
                  pending: {
                    $sum: {
                      $cond: [{ $eq: ["$release_status", "pending"] }, 1, 0],
                    },
                  },
                  releasedCount: {
                    $sum: {
                      $cond: [{ $eq: ["$release_status", "released"] }, 1, 0],
                    },
                  },
                  upcomingCount: {
                    $sum: {
                      $cond: [{ $eq: ["$release_status", "upcoming"] }, 1, 0],
                    },
                  },
                  views: { $sum: { $ifNull: ["$views", 0] } },
                  totalSales: { $sum: { $ifNull: ["$sold", 0] } },
                },
              },
            ])
            .toArray();

          // 2. Analytics
          const paymentAnalytics = await paymentsCollection
            .aggregate([
              { $match: { movie_owner_email: email, status: "success" } },
              { $addFields: { dateObj: { $toDate: "$createdAt" } } },
              {
                $addFields: {
                  dateObj: { $toDate: "$createdAt" },
                  numericAmount: { $toDouble: "$amount" },
                },
              },
              {
                $group: {
                  _id: { $dateToString: { format: "%Y-%m", date: "$dateObj" } },
                  earnings: { $sum: { $multiply: ["$numericAmount", 0.8] } },
                  sales: { $sum: 1 },
                },
              },
              { $sort: { _id: 1 } },
            ])
            .toArray();

          // 3. Top Movies
          const topMovies = await movieCollection
            .find({ email })
            .sort({ sold: -1, views: -1 })
            .limit(5)
            .project({ title: 1, sold: 1, views: 1, poster: 1 })
            .toArray();

          // 4. Recent Transactions
          const recentTransactions = await paymentsCollection
            .find({ movie_owner_email: email, status: "success" })
            .sort({ createdAt: -1 })
            .limit(5)
            .toArray();

          const statsResult = movieStats[0] || {
            totalMovies: 0,
            approved: 0,
            pending: 0,
            releasedCount: 0,
            upcomingCount: 0,
            views: 0,
            totalSales: 0,
          };

          const totalEarnings = paymentAnalytics.reduce(
            (sum, item) => sum + (item.earnings || 0),
            0,
          );

          res.json({
            stats: { ...statsResult, earnings: totalEarnings },
            analytics: {
              earnings: paymentAnalytics.map((item) => ({
                month: new Date(item._id + "-01").toLocaleString("default", {
                  month: "short",
                }),
                value: item.earnings,
              })),
              sales: paymentAnalytics.map((item) => ({
                month: new Date(item._id + "-01").toLocaleString("default", {
                  month: "short",
                }),
                value: item.sales,
              })),
            },
            topMovies: topMovies || [],
            recentTransactions: recentTransactions || [],
          });
        } catch (error) {
          console.error(error);
          res.status(500).json({ message: "Internal Server Error" });
        }
      },
    );

    /*
    -------------------------
    POST: User Apply for Become Partner API
    -------------------------
    */

    app.post("/apply/become-partner", verifyAccessToken, async (req, res) => {
      try {
        const { fullName, reason } = req.body;

        // get user from token
        const userId = req.decoded?.id;
        const email = req.decoded?.email;

        const user = await usersCollection.findOne({
          _id: new ObjectId(userId),
        });

        if (user.role === "admin") {
          return res.status(403).json({
            message:
              "Access Denied: Admins cannot submit partner applications.",
          });
        }

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
          applied_at: new Date(),
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
    GET: My Application status API
    -------------------------
    */

    app.get("/my-application", verifyAccessToken, async (req, res) => {
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
    GET: All partner application list for Admin API
    -------------------------
    */

    app.get(
      "/admin/all-partner-applications",
      verifyAccessToken,
      verifyAdmin,
      async (req, res) => {
        try {
          // If it passed the two middlewares above, we don't need an extra 'if' check here
          const result = await partnerApplicationsCollection
            .find()
            .sort({ applied_at: -1 })
            .toArray();

          res.status(200).json({
            success: true,
            data: result,
          });
        } catch (error) {
          res.status(500).json({ success: false, message: error.message });
        }
      },
    );

    /*
    -------------------------
    PATCH:Partner application approve or Reject By Admin
    -------------------------
    */
    app.patch(
      "/admin/application-update-status/:id",
      verifyAccessToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const { status } = req.body;

        try {
          const filter = { _id: new ObjectId(id) };
          const updateDoc = {
            $set: { status },
          };

          const result = await partnerApplicationsCollection.updateOne(
            filter,
            updateDoc,
          );

          if (result.modifiedCount > 0) {
            res.json({
              success: true,
              message: "Application approved! User can now pay.",
            });
          } else {
            res
              .status(404)
              .json({ success: false, message: "Application not found" });
          }
        } catch (error) {
          console.error("Approve Error:", error);
          res.json(500).send({ message: "Internal Server Error" });
        }
      },
    );

    /*
    -------------------------
    PATCH: Update single User Status By Admin API
    -------------------------
    */

    app.patch(
      "/admin/manage-user/:id",
      verifyAccessToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const { role, status } = req.body;
          const filter = { _id: new ObjectId(id) };

          if (req.user?.id === id) {
            return res.status(403).json({
              success: false,
              message: "You cannot modify your own administrative permissions.",
            });
          }

          const updateDoc = {
            $set: {},
          };

          if (role) updateDoc.$set.role = role;
          if (status) updateDoc.$set.status = status;

          const result = await usersCollection.updateOne(filter, updateDoc);

          if (result.matchedCount === 0) {
            return res
              .status(404)
              .json({ success: false, message: "User not found" });
          }

          res.status(200).json({
            success: true,
            message: "User updated successfully",
          });
        } catch (error) {
          res.status(500).json({
            success: false,
            message: error.message || "Failed to update user",
          });
        }
      },
    );

    /*
    -------------------------
    GET: Single Movies API
    -------------------------
    */

    app.get("/movies/:id", async (req, res) => {
      try {
        const movieId = req?.params?.id;

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

    /*
    -------------------------
    PATCH: Single Movie Update
    -------------------------
    */

    app.patch("/movies/:id", verifyAccessToken, async (req, res) => {
      try {
        const id = req.params.id;
        const updatedData = req.body;
        const email = req?.decoded?.email;

        const user = await usersCollection.findOne({ email });
        const role = user?.role;

        if (role !== "admin" && role !== "partner") {
          return res.status(403).json({
            success: false,
            message: "Forbidden: You do not have permission to add movies.",
          });
        }

        const movie = await movieCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!movie) {
          return res.status(404).json({ message: "Movie not found" });
        }

        if (role !== "admin") {
          if (movie.email !== email) {
            return res.status(403).json({ message: "Forbidden" });
          }
        }

        const result = await movieCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData },
        );

        res.json(result);
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Failed to update movie" });
      }
    });

    /*
    -------------------------
    GET: single Application API for payment
    -------------------------
    */

    app.get(
      "/partner/applications/:id",
      verifyAccessToken,
      async (req, res) => {
        try {
          const id = req.params.id;
          const userId = req.decoded?.id;

          const application = await partnerApplicationsCollection.findOne({
            _id: new ObjectId(id),
            userId,
          });

          if (!application) {
            return res.status(404).json({ message: "Not found" });
          }

          res.json(application);
        } catch (error) {
          console.error(error);
          res.status(500).json({ message: "Server error" });
        }
      },
    );

    /*
    -------------------------
    PATCH: Api for increase views in details page visit 
    -------------------------
    */

    app.patch("/movies/:id/view", async (req, res) => {
      try {
        const id = req.params.id;

        const { role } = req.body;

        // block admin & partner
        if (role === "admin" || role === "partner") {
          return res.json({
            success: true,
            message: "View not counted",
          });
        }

        const result = await movieCollection.updateOne(
          { _id: new ObjectId(id) },
          { $inc: { views: 1 } },
        );

        res.json({ success: true, result });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    /*
    -------------------------
    PATCH: update user name and profile pic 
    -------------------------
    */

    app.patch(
      "/users/update-profile/:id",
      verifyAccessToken,
      async (req, res) => {
        try {
          const idFromURL = req.params.id;
          const idFromToken = req.decoded?.id; //

          // Ensure the person logged in is the same person being updated
          if (idFromURL !== idFromToken) {
            return res.status(403).json({
              success: false,
              message: "Forbidden: You can only update your own profile.",
            });
          }

          const { fullName, profilePic } = req.body;

          // 2. Database Update Logic
          const filter = { _id: new ObjectId(idFromURL) };
          const updateDoc = {
            $set: {
              fullName: fullName,
              profilePic: profilePic,
            },
          };

          const result = await usersCollection.updateOne(filter, updateDoc);

          if (result.matchedCount === 0) {
            return res
              .status(404)
              .json({ success: false, message: "User not found" });
          }

          // 3. Fetch updated data to send back to frontend
          const updatedUser = await usersCollection.findOne(filter, {
            projection: { password: 0 }, // Don't send the password back
          });

          res.status(200).json({
            success: true,
            message: "Profile updated successfully",
            user: updatedUser,
          });
        } catch (error) {
          console.error("Update Profile Error:", error);
          res
            .status(500)
            .json({ success: false, message: "Internal Server Error" });
        }
      },
    );

    /*
    -------------------------
    GET: Related Movies
    -------------------------
    */

    app.get("/movies/related/:id", async (req, res) => {
      try {
        const id = req.params.id;

        const currentMovie = await movieCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!currentMovie) {
          return res.status(404).send({ message: "Movie not found" });
        }

        const relatedMovies = await movieCollection
          .find({
            _id: { $ne: new ObjectId(id) },
            genres: { $in: currentMovie.genres || [] },
          })
          .limit(4)
          .toArray();

        res.json(relatedMovies);
      } catch (error) {
        res.status(500).json({ message: "Server error" });
      }
    });

    /*
    -------------------------
    DELETE: Single Movie 
    -------------------------
    */

    app.delete(
      "/movies/:id",
      verifyAccessToken,

      async (req, res) => {
        try {
          const id = req.params.id;
          const email = req.decoded.email;

          const user = await usersCollection.findOne({ email });
          const role = user?.role;

          if (role !== "admin" && role !== "partner") {
            return res.status(403).json({
              success: false,
              message:
                "Forbidden: You do not have permission to delete movies.",
            });
          }

          const movie = await movieCollection.findOne({
            _id: new ObjectId(id),
          });

          if (!movie) {
            return res.status(404).json({ message: "Movie not found" });
          }

          // only restrict non-admin
          if (role !== "admin") {
            if (movie.email !== email) {
              return res.status(403).json({
                message: "Not allowed",
              });
            }
          }

          const result = await movieCollection.deleteOne({
            _id: new ObjectId(id),
          });

          res.json({ success: true, message: "Deleted successfully" });
        } catch (error) {
          console.error(error);
          res.status(500).json({ message: "Internal server error" });
        }
      },
    );

    /*
    -------------------------
    POST: Make Payment Intent API
    -------------------------
    */

    app.post("/create-payment-intent", verifyAccessToken, async (req, res) => {
      try {
        const { amount, referenceId } = req.body;

        const parsedAmount = Number(amount);

        let isValid = false;

        const application = await partnerApplicationsCollection.findOne({
          _id: new ObjectId(referenceId),
        });

        //BLOCK if not approved
        if (application) {
          if (application.status !== "approved") {
            return res.status(403).send({
              success: false,
              message: "Application not approved.",
            });
          }
          isValid = true;
        }

        // If not application, check if it's a movie
        if (!application) {
          const movie = await movieCollection.findOne({
            _id: new ObjectId(referenceId),
          });

          if (!movie) {
            return res.status(404).send({
              success: false,
              message: "Invalid reference ID",
            });
          }

          isValid = true;
        }

        if (isValid) {
          const paymentIntent = await stripe.paymentIntents.create({
            amount: Math.round(parsedAmount * 100),
            currency: "usd",
            payment_method_types: ["card"],
          });

          return res.json({
            clientSecret: paymentIntent.client_secret,
          });
        }
      } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Payment Intent failed" });
      }
    });

    /*
    -------------------------
    POST: Store payment details and update user role
    -------------------------
    */

    app.post("/payments", verifyAccessToken, async (req, res) => {
      const payment = req.body;

      // Prevent duplicate payment for user and partner
      const existingPayment = await paymentsCollection.findOne({
        referenceId: payment.referenceId,
        email: req.decoded.email,
      });

      if (existingPayment) {
        return res.status(409).json({
          success: false,
          message: "Payment already exists",
        });
      }

      // ---------------------
      // Partner PAYMENT LOGIC
      // ---------------------

      if (payment?.type === "partner") {
        const application = await partnerApplicationsCollection.findOne({
          _id: new ObjectId(payment?.referenceId),
        });

        // If application not found
        if (!application) {
          return res.status(403).json({
            success: false,
            message: "Payment not allowed",
          });
        }

        // BLOCK if application not approved
        if (application.status !== "approved") {
          return res.status(403).json({
            success: false,
            message: "Payment not allowed. Application not approved.",
          });
        }

        // check user ownership
        if (application.email !== payment.email) {
          return res.status(403).send({
            success: false,
            message: "Unauthorized user",
          });
        }

        if (application.paymentStatus === "paid") {
          return res.status(409).json({
            success: false,
            message: "Already paid",
          });
        }

        const result = await paymentsCollection.insertOne(payment);

        // update the partnerApplication

        await partnerApplicationsCollection.updateOne(
          { _id: new ObjectId(payment?.referenceId) },
          {
            $set: {
              paymentStatus: "paid",
              transactionId: payment?.transactionId,
            },
          },
        );

        // promote user
        await usersCollection.updateOne(
          { email: payment.email },
          { $set: { role: "partner" } },
        );

        return res.json({
          success: true,
          insertedId: result.insertedId,
        });
      }

      // ---------------------
      // MOVIE PAYMENT LOGIC
      // ---------------------
      if (payment.type === "movie") {
        const movie = await movieCollection.findOne({
          _id: new ObjectId(payment.referenceId),
        });

        // check movie exists
        if (!movie) {
          return res.status(404).json({
            success: false,
            message: "Movie not found",
          });
        }

        // Prevent buying same movie twice
        const user = await usersCollection.findOne({
          email: payment.email,
        });

        if (user?.purchasedMovies?.includes(payment.referenceId)) {
          return res.status(409).json({
            success: false,
            message: "Movie already purchased",
          });
        }

        const enrichedPayment = {
          ...payment,
          movie_owner_email: movie.email,
          added_by: movie.added_by,
        };

        const result = await paymentsCollection.insertOne(enrichedPayment);

        // Save purchased movie
        await usersCollection.updateOne(
          { email: payment.email },
          {
            $addToSet: { purchasedMovies: payment.referenceId },
          },
        );

        // INCREASE SOLD COUNT IN MOVIE COLLECTION

        await movieCollection.updateOne(
          { _id: new ObjectId(payment.referenceId) },
          {
            $inc: { sold: 1 },
          },
        );

        return res.json({
          success: true,
          insertedId: result.insertedId,
        });
      }

      return res.status(400).json({
        success: false,
        message: "Invalid payment type",
      });
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
