const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();
const stripe = require("stripe")(process.env.PAYMENT_SECRET_KEY);
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

const verifyJWT = (req, res, next) => {
	const authorization = req.headers.authorization;
	if (!authorization) {
		return res.status(401).send({ error: true, message: "Invalid Token" });
	}
	// Bearer token
	const token = authorization.split(" ")[1];
	jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
		if (err) {
			return res.status(401).send({ error: true, message: "Invalid Token" });
		}
		req.decoded = decoded;
		next();
	});
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.bq2ef3t.mongodb.net/?retryWrites=true&w=majority`;

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
		// Connect the client to the server	(optional starting in v4.7)
		await client.connect();

		const usersCollection = client.db("bistroDB").collection("users");
		const menuCollection = client.db("bistroDB").collection("menu");
		const reviewCollection = client.db("bistroDB").collection("reviews");
		const cartCollection = client.db("bistroDB").collection("carts");
		const paymentCollection = client.db("bistroDB").collection("payments");

		// JWT tokens
		app.post("/jwt", (req, res) => {
			const user = req.body;
			const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "1h" });
			res.send({ token });
		});

		// Warning: Use verify JWT before using verifyAdmin
		const verifyAdmin = async (req, res, next) => {
			const email = req.decoded.email;
			const query = { email: email };
			const user = await usersCollection.findOne(query);
			if (user?.role !== "admin") {
				return res.status(403).send({ error: true, message: "Forbidden message" });
			}
			next();
		};

		// Users collection
		app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
			const result = await usersCollection.find().toArray();
			res.send(result);
		});

		app.post("/users", async (req, res) => {
			const user = req.body;
			const query = { email: user.email };
			const existingUser = await usersCollection.findOne(query);
			if (existingUser) {
				return res.send({ message: "User already exists" });
			}
			const result = await usersCollection.insertOne(user);
			res.send(result);
		});

		// Security layer: verify JWT token
		// Email same
		// Check email
		app.get("/users/admin/:email", verifyJWT, async (req, res) => {
			const email = req.params.email;

			if (req.decoded.email !== email) {
				res.send({ admin: false });
			}

			const query = { email: email };
			const user = await usersCollection.findOne(query);
			const result = { admin: user?.role === "admin" };
			res.send(result);
		});

		app.patch("/users/admin/:id", async (req, res) => {
			const id = req.params.id;
			const filter = { _id: new ObjectId(id) };
			const updatedDoc = {
				$set: {
					role: "admin",
				},
			};
			const result = await usersCollection.updateOne(filter, updatedDoc);
			res.send(result);
		});

		// Menu collection
		app.get("/menu", async (req, res) => {
			const result = await menuCollection.find().toArray();
			res.send(result);
		});

		app.post("/menu", verifyJWT, verifyAdmin, async (req, res) => {
			const newItem = req.body;
			const result = await menuCollection.insertOne(newItem);
			res.send(result);
		});

		app.delete("/menu/:id", verifyJWT, verifyAdmin, async (req, res) => {
			const id = req.params.id;
			const query = { _id: new ObjectId(id) };
			const result = await menuCollection.deleteOne(query);
			res.send(result);
		});

		// Review collection
		app.get("/reviews", async (req, res) => {
			const result = await reviewCollection.find().toArray();
			res.send(result);
		});

		// Cart collection
		app.get("/carts", verifyJWT, async (req, res) => {
			const email = req.query.email;

			if (!email) {
				res.send([]);
			}

			const decodedEmail = req.decoded.email;
			if (email !== decodedEmail) {
				return res.status(403).send({ error: true, message: "Forbidden access" });
			}

			const query = { email: email };
			const result = await cartCollection.find(query).toArray();
			res.send(result);
		});

		app.post("/carts", async (req, res) => {
			const item = req.body;
			console.log(item);
			const result = await cartCollection.insertOne(item);
			res.send(result);
		});

		app.delete("/carts/:id", async (req, res) => {
			const id = req.params.id;
			const query = { _id: new ObjectId(id) };
			const result = await cartCollection.deleteOne(query);
			res.send(result);
		});

		// Create payment intent
		app.post("/create-payment-intent", verifyJWT, async (req, res) => {
			const { price } = req.body;
			const amount = price * 100;

			const paymentIntent = await stripe.paymentIntents.create({
				amount: amount,
				currency: "usd",
				payment_method_types: ["card"],
			});

			res.send({
				clientSecret: paymentIntent.client_secret,
			});
		});

		// Payment related intent
		app.post("/payments", verifyJWT, async (req, res) => {
			const payment = req.body;
			const insertResult = await paymentCollection.insertOne(payment);
			const query = { _id: { $in: payment.cartItems.map((id) => new ObjectId(id)) } };
			const deleteResult = await cartCollection.deleteMany(query);
			res.send({ insertResult, deleteResult });
		});

		app.get("/admin-stats", verifyJWT, verifyAdmin, async (req, res) => {
			const users = await usersCollection.estimatedDocumentCount();
			const products = await menuCollection.estimatedDocumentCount();
			const orders = await paymentCollection.estimatedDocumentCount();
			const payments = await paymentCollection.find().toArray();
			const revenue = payments.reduce((sum, payment) => sum + payment.price, 0);
			res.send({ users, products, orders, revenue });
		});

		app.get("/order-stats", verifyJWT, verifyAdmin, async (req, res) => {
			const pipeline = [
				{
					$lookup: {
						from: "menu",
						localField: "menuItems",
						foreignField: "_id",
						as: "menuItemsData",
					},
				},
				{
					$unwind: "$menuItemsData",
				},
				{
					$group: {
						_id: "$menuItemsData.category",
						count: { $sum: 1 },
						total: { $sum: "$menuItemsData.price" },
					},
				},
				{
					$project: {
						category: "$_id",
						count: 1,
						total: { $round: ["$total", 2] },
						_id: 0,
					},
				},
			];
			const result = await paymentCollection.aggregate(pipeline).toArray();
			res.send(result);
		});

		// Send a ping to confirm a successful connection
		await client.db("admin").command({ ping: 1 });
		console.log("Pinged your deployment. You successfully connected to MongoDB!");
	} finally {
		// Ensures that the client will close when you finish/error
		// await client.close();
	}
}
run().catch(console.dir);

app.get("/", (req, res) => {
	res.send("Bistro Boss is running");
});

app.listen(port, () => {
	console.log(`Bistro Boss is running on port: ${port}`);
});
