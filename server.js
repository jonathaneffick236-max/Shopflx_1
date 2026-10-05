const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json({ limit: "10mb" }));

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

/* =========================
   DATABASE
========================= */

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'customer',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      seller_id INTEGER,
      name TEXT NOT NULL,
      description TEXT,
      category TEXT,
      price NUMERIC(12,2) NOT NULL,
      old_price NUMERIC(12,2),
      image_url TEXT,
      stock INTEGER DEFAULT 0,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      customer_name TEXT NOT NULL,
      customer_phone TEXT NOT NULL,
      region TEXT,
      address TEXT NOT NULL,
      total NUMERIC(12,2) NOT NULL,
      payment_method TEXT,
      payment_reference TEXT,
      payment_status TEXT DEFAULT 'pending',
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS order_items (
      id SERIAL PRIMARY KEY,
      order_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      quantity INTEGER NOT NULL,
      price NUMERIC(12,2) NOT NULL
    );
  `);

  console.log("Database ready");
}

/* =========================
   AUTHENTICATION
========================= */

function authenticateToken(req, res, next) {
  if (!JWT_SECRET) {
    return res.status(500).json({
      error: "JWT secret is not configured"
    });
  }

  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication required"
    });
  }

  const token = authHeader.substring(7);

  try {
    const user = jwt.verify(token, JWT_SECRET);

    req.user = user;

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}

function requireSellerOrAdmin(req, res, next) {
  if (
    req.user.role !== "seller" &&
    req.user.role !== "admin"
  ) {
    return res.status(403).json({
      error: "Seller or admin access required"
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      error: "Admin access required"
    });
  }

  next();
}

/* =========================
   HOME
========================= */

app.get("/", (req, res) => {
  res.json({
    status: "online",
    app: "SHOPFLIX",
    message: "SHOPFLIX backend is running"
  });
});

/* =========================
   HEALTH
========================= */

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      database: "connected",
      paystack: PAYSTACK_SECRET_KEY
        ? "configured"
        : "not configured",
      jwt: JWT_SECRET
        ? "configured"
        : "not configured"
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      status: "error",
      database: "disconnected"
    });
  }
});

/* =========================
   PRODUCTS
========================= */

app.get("/api/products", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT *
      FROM products
      WHERE active = TRUE
      ORDER BY created_at DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load products"
    });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT *
      FROM products
      WHERE id = $1
      `,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Product not found"
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load product"
    });
  }
});

/* =========================
   CREATE PRODUCT
   SELLER / ADMIN ONLY
========================= */

app.post(
  "/api/products",
  authenticateToken,
  requireSellerOrAdmin,
  async (req, res) => {
    try {
      const {
        name,
        description,
        category,
        price,
        old_price,
        image_url,
        stock
      } = req.body;

      if (!name || price === undefined) {
        return res.status(400).json({
          error: "Product name and price are required"
        });
      }

      const result = await pool.query(
        `
        INSERT INTO products
        (
          seller_id,
          name,
          description,
          category,
          price,
          old_price,
          image_url,
          stock
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        RETURNING *
        `,
        [
          req.user.id,
          name,
          description || "",
          category || "Other",
          price,
          old_price || null,
          image_url || "",
          Number(stock) || 0
        ]
      );

      res.status(201).json(result.rows[0]);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not create product"
      });
    }
  }
);

/* =========================
   SELLER PRODUCTS
========================= */

app.get(
  "/api/seller/products",
  authenticateToken,
  requireSellerOrAdmin,
  async (req, res) => {
    try {
      let result;

      if (req.user.role === "admin") {
        result = await pool.query(`
          SELECT *
          FROM products
          ORDER BY created_at DESC
        `);
      } else {
        result = await pool.query(
          `
          SELECT *
          FROM products
          WHERE seller_id = $1
          ORDER BY created_at DESC
          `,
          [req.user.id]
        );
      }

      res.json(result.rows);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not load seller products"
      });
    }
  }
);

/* =========================
   REGISTER
========================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      name,
      email,
      phone,
      password
    } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Name, email and password are required"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must be at least 6 characters"
      });
    }

    const normalizedEmail =
      email.toLowerCase().trim();

    const existing = await pool.query(
      `
      SELECT id
      FROM users
      WHERE email = $1
      `,
      [normalizedEmail]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: "Account already exists"
      });
    }

    const hashedPassword =
      await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
      INSERT INTO users
      (
        name,
        email,
        phone,
        password,
        role
      )
      VALUES ($1,$2,$3,$4,'customer')
      RETURNING
        id,
        name,
        email,
        phone,
        role,
        created_at
      `,
      [
        name,
        normalizedEmail,
        phone || null,
        hashedPassword
      ]
    );

    res.status(201).json({
      message: "Account created",
      user: result.rows[0]
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Registration failed"
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/auth/login", async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required"
      });
    }

    const result = await pool.query(
      `
      SELECT *
      FROM users
      WHERE email = $1
      `,
      [email.toLowerCase().trim()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    const safeUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      role: user.role,
      created_at: user.created_at
    };

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    res.json({
      message: "Login successful",
      token,
      user: safeUser
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Login failed"
    });
  }
});

/* =========================
   CURRENT USER
========================= */

app.get(
  "/api/auth/me",
  authenticateToken,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          name,
          email,
          phone,
          role,
          created_at
        FROM users
        WHERE id = $1
        `,
        [req.user.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "User not found"
        });
      }

      res.json({
        user: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not load account"
      });
    }
  }
);

/* =========================
   CREATE ORDER
========================= */

app.post("/api/orders", async (req, res) => {
  const client = await pool.connect();

  try {
    const {
      user_id,
      customer_name,
      customer_phone,
      region,
      address,
      payment_method,
      items
    } = req.body;

    if (
      !customer_name ||
      !customer_phone ||
      !address ||
      !Array.isArray(items) ||
      items.length === 0
    ) {
      return res.status(400).json({
        error: "Incomplete order"
      });
    }

    await client.query("BEGIN");

    let total = 0;
    const orderItems = [];

    for (const item of items) {
      const productResult = await client.query(
        `
        SELECT *
        FROM products
        WHERE id = $1
        AND active = TRUE
        `,
        [item.product_id]
      );

      if (productResult.rows.length === 0) {
        throw new Error(
          `Product ${item.product_id} not found`
        );
      }

      const product = productResult.rows[0];

      const quantity = Math.max(
        1,
        Number(item.quantity) || 1
      );

      if (product.stock < quantity) {
        throw new Error(
          `${product.name} is out of stock`
        );
      }

      total +=
        Number(product.price) * quantity;

      orderItems.push({
        product_id: product.id,
        quantity,
        price: product.price
      });
    }

    const orderResult = await client.query(
      `
      INSERT INTO orders
      (
        user_id,
        customer_name,
        customer_phone,
        region,
        address,
        total,
        payment_method,
        payment_status,
        status
      )
      VALUES
      ($1,$2,$3,$4,$5,$6,$7,'pending','pending')
      RETURNING *
      `,
      [
        user_id || null,
        customer_name,
        customer_phone,
        region || "",
        address,
        total,
        payment_method || "Paystack"
      ]
    );

    const order = orderResult.rows[0];

    for (const item of orderItems) {
      await client.query(
        `
        INSERT INTO order_items
        (
          order_id,
          product_id,
          quantity,
          price
        )
        VALUES ($1,$2,$3,$4)
        `,
        [
          order.id,
          item.product_id,
          item.quantity,
          item.price
        ]
      );
    }

    await client.query("COMMIT");

    res.status(201).json({
      message: "Order created",
      order
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(error);

    res.status(400).json({
      error: error.message
    });
  } finally {
    client.release();
  }
});

/* =========================
   PAYSTACK INITIALIZE
========================= */

app.post(
  "/api/payments/initialize",
  async (req, res) => {
    try {
      if (!PAYSTACK_SECRET_KEY) {
        return res.status(500).json({
          error: "Paystack secret key is not configured"
        });
      }

      const {
        order_id,
        email
      } = req.body;

      if (!order_id || !email) {
        return res.status(400).json({
          error: "Order ID and email are required"
        });
      }

      const orderResult = await pool.query(
        `
        SELECT *
        FROM orders
        WHERE id = $1
        `,
        [order_id]
      );

      if (orderResult.rows.length === 0) {
        return res.status(404).json({
          error: "Order not found"
        });
      }

      const order = orderResult.rows[0];

      if (order.payment_status === "paid") {
        return res.status(400).json({
          error: "Order has already been paid"
        });
      }

      const amountInPesewas = Math.round(
        Number(order.total) * 100
      );

      const response = await axios.post(
        "https://api.paystack.co/transaction/initialize",
        {
          email,
          amount: amountInPesewas,
          currency: "GHS",
          reference:
            `SHOPFLIX-${order.id}-${Date.now()}`,
          metadata: {
            order_id: order.id
          }
        },
        {
          headers: {
            Authorization:
              `Bearer ${PAYSTACK_SECRET_KEY}`,
            "Content-Type":
              "application/json"
          }
        }
      );

      if (!response.data.status) {
        return res.status(400).json({
          error:
            response.data.message ||
            "Paystack initialization failed"
        });
      }

      const reference =
        response.data.data.reference;

      await pool.query(
        `
        UPDATE orders
        SET payment_reference = $1
        WHERE id = $2
        `,
        [reference, order.id]
      );

      res.json({
        status: true,
        authorization_url:
          response.data.data.authorization_url,
        access_code:
          response.data.data.access_code,
        reference
      });
    } catch (error) {
      console.error(
        "Paystack initialize error:",
        error.response?.data ||
        error.message
      );

      res.status(500).json({
        error:
          error.response?.data?.message ||
          "Could not initialize Paystack payment"
      });
    }
  }
);

/* =========================
   PAYSTACK VERIFY
========================= */

app.get(
  "/api/payments/verify/:reference",
  async (req, res) => {
    const client = await pool.connect();

    try {
      if (!PAYSTACK_SECRET_KEY) {
        return res.status(500).json({
          error: "Paystack secret key is not configured"
        });
      }

      const reference = req.params.reference;

      const response = await axios.get(
        `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
        {
          headers: {
            Authorization:
              `Bearer ${PAYSTACK_SECRET_KEY}`
          }
        }
      );

      if (!response.data.status) {
        return res.status(400).json({
          error:
            response.data.message ||
            "Payment verification failed"
        });
      }

      const payment = response.data.data;

      if (payment.status !== "success") {
        return res.status(400).json({
          error: "Payment was not successful",
          payment_status: payment.status
        });
      }

      const orderResult = await client.query(
        `
        SELECT *
        FROM orders
        WHERE payment_reference = $1
        `,
        [reference]
      );

      if (orderResult.rows.length === 0) {
        return res.status(404).json({
          error: "SHOPFLIX order not found"
        });
      }

      const order = orderResult.rows[0];

      if (order.payment_status === "paid") {
        return res.json({
          status: true,
          message: "Payment already verified",
          order
        });
      }

      const paidAmount = Number(payment.amount);

      const expectedAmount = Math.round(
        Number(order.total) * 100
      );

      if (paidAmount !== expectedAmount) {
        return res.status(400).json({
          error: "Payment amount does not match order"
        });
      }

      await client.query("BEGIN");

      const itemsResult = await client.query(
        `
        SELECT *
        FROM order_items
        WHERE order_id = $1
        `,
        [order.id]
      );

      for (const item of itemsResult.rows) {
        const productResult = await client.query(
          `
          SELECT *
          FROM products
          WHERE id = $1
          FOR UPDATE
          `,
          [item.product_id]
        );

        if (productResult.rows.length === 0) {
          throw new Error(
            `Product ${item.product_id} not found`
          );
        }

        const product = productResult.rows[0];

        if (product.stock < item.quantity) {
          throw new Error(
            `${product.name} is no longer available in the requested quantity`
          );
        }

        await client.query(
          `
          UPDATE products
          SET stock = stock - $1
          WHERE id = $2
          `,
          [
            item.quantity,
            item.product_id
          ]
        );
      }

      const updatedOrderResult =
        await client.query(
          `
          UPDATE orders
          SET
            payment_status = 'paid',
            status = 'paid'
          WHERE id = $1
          RETURNING *
          `,
          [order.id]
        );

      await client.query("COMMIT");

      res.json({
        status: true,
        message: "Payment verified successfully",
        order: updatedOrderResult.rows[0]
      });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {}

      console.error(
        "Paystack verify error:",
        error.response?.data ||
        error.message
      );

      res.status(500).json({
        error:
          error.response?.data?.message ||
          error.message ||
          "Payment verification failed"
      });
    } finally {
      client.release();
    }
  }
);

/* =========================
   ORDER
========================= */

app.get(
  "/api/orders/:id",
  async (req, res) => {
    try {
      const orderResult = await pool.query(
        `
        SELECT *
        FROM orders
        WHERE id = $1
        `,
        [req.params.id]
      );

      if (orderResult.rows.length === 0) {
        return res.status(404).json({
    
