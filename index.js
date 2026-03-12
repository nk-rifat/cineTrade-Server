const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion } = require("mongodb");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Atlas Connection URI
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.v0ym3.mongodb.net/?appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server
    await client.connect();

    // Define your Database and Collection
    const db = client.db("cineTradeDB");
    const movieCollection = db.collection("movies");


    // GET: Fetch all movies from the database
    app.get('/movies', async (req, res) => {
      try {
        const result = await movieCollection.find().toArray();
        
        res.status(200).send(result);
      } catch (error) {
        console.error("Error fetching movies:", error);
        res.status(500).send({ 
          success: false, 
          message: "Internal Server Error" 
        });
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
