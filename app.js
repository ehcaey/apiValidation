const jwt = require("jsonwebtoken");
const express = require("express");
const bodyParser = require("body-parser");
const { body, validationResult } = require("express-validator");
const app = express();
const port = 3000;

app.use(bodyParser.json());

const users = [];
let userIdCounter = 1;

function isEmailUnique(email) {
  return !users.some((user) => user.email === email);
}

function validateUser(user) {
  const errors = {};

  if (!user.fullName) {
    errors.fullName = "Nama lengkap harus diisi";
  }

  if (!user.email) {
    errors.email = "Email harus diisi";
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(user.email)) {
    errors.email = "Email tidak valid";
  } else if (!isEmailUnique(user.email)) {
    errors.email = "Email sudah terdaftar";
  }

  if (!user.password) {
    errors.password = "Password harus diisi";
  } else if (user.password.length < 8) {
    errors.password = "Password harus minimal 8 karakter";
  } else if (!/[!@#$%^&*]/.test(user.password)) {
    errors.password = "Password harus memiliki minimal 1 simbol";
  }

  if (!user.dob) {
    errors.dob = "Tanggal lahir harus diisi";
  } else if (!/^\d{4}-\d{2}-\d{2}$/.test(user.dob)) {
    errors.dob = "Format tanggal lahir harus YYYY-MM-DD";
  }

  return errors;
}

app.post(
  "/auth/register",
  [
    body("fullName").notEmpty().withMessage("Nama lengkap harus diisi"),
    body("email")
      .notEmpty()
      .withMessage("Email harus diisi")
      .isEmail()
      .withMessage("Email tidak valid")
      .custom((value) => {
        if (!isEmailUnique(value)) {
          throw new Error("Email sudah terdaftar");
        }
        return true;
      }),
    body("password")
      .notEmpty()
      .withMessage("Password harus diisi")
      .isLength({ min: 8 })
      .withMessage("Password harus minimal 8 karakter")
      .matches(/[!@#$%^&*]/)
      .withMessage("Password harus memiliki minimal 1 simbol"),
    body("dob")
      .notEmpty()
      .withMessage("Tanggal lahir harus diisi")
      .isDate()
      .withMessage("Format tanggal lahir harus YYYY-MM-DD"),
  ],
  (req, res) => {
    const userData = req.body;
    const errors = validationResult(req);

    if (errors.isEmpty()) {
      const userId = userIdCounter++;

      const newUser = {
        id: userId,
        fullName: userData.fullName,
        email: userData.email,
        password: userData.password,
        bio: userData.bio || "",
        dob: userData.dob,
      };

      users.push(newUser);

      res.status(201).json({ message: "Success" });
    } else {
      res
        .status(400)
        .json({ message: "Validation Error", detail: errors.array() });
    }
  }
);

app.post(
  "/auth/login",
  [
    body("email")
      .notEmpty()
      .withMessage("Email harus diisi")
      .isEmail()
      .withMessage("Email tidak valid"),
    body("password")
      .notEmpty()
      .withMessage("Password harus diisi")
      .isLength({ min: 8 })
      .withMessage("Password harus minimal 8 karakter")
      .matches(/[!@#$%^&*]/)
      .withMessage("Password harus memiliki minimal 1 simbol"),
  ],
  (req, res) => {
    const { email, password } = req.body;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      res
        .status(400)
        .json({ message: "Validation Error", detail: errors.array() });
    } else {
      const user = users.find((user) => user.email === email);

      if (!user) {
        return res.status(401).json({ message: "Login Failed" });
      }

      if (user.password !== password) {
        return res.status(401).json({ message: "Login Failed" });
      }

      const token = jwt.sign({ id: user.id, email: user.email }, "secret-key", {
        expiresIn: "1h",
      });

      res.status(200).json({ message: "Success", data: { token } });
    }
  }
);

app.get("/users", (req, res) => {
  if (users.length > 0) {
    const userData = users.map((user) => {
      return {
        fullName: user.fullName,
        email: user.email,
        bio: user.bio,
        dob: user.dob,
      };
    });

    res.status(200).json({ message: "Success", data: userData });
  } else {
    res.status(404).json({ message: "User not found" });
  }
});

function findUserById(userId) {
  return users.find((user) => user.id === userId);
}

function isUserIdValid(userId) {
  return /^\d+$/.test(userId);
}

app.get("/users/:userId", (req, res) => {
  const userId = parseInt(req.params.userId);

  if (!isUserIdValid(userId)) {
    res
      .status(400)
      .json({ message: "Validation Error", detail: { userId: "Harus angka" } });
  } else {
    const user = findUserById(userId);

    if (user) {
      res.status(200).json({
        message: "Success",
        data: {
          fullName: user.fullName,
          email: user.email,
          bio: user.bio,
          dob: user.dob,
        },
      });
    } else {
      res.status(404).json({ message: "User not found" });
    }
  }
});

app.listen(port, () => {
  console.log(`Server berjalan di http://localhost:${port}`);
});
