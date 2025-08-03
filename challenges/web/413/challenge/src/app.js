import express from "express";
import path from "path";
import { fileURLToPath } from "url";

const app = express();

app.use(function (req, res, next) {
  if (req.method === "POST") {
    const contentType = req.headers["content-type"];

    if (!contentType) {
      return res.status(400).json({
        error: "Content-Type header is required.",
      });
    }

    if (contentType !== "application/x-www-form-urlencoded") {
      return res.status(400).json({
        error: "Invalid Content-Type",
      });
    }
  }

  next();
});

app.use(express.urlencoded({ extended: true }));

const PORT = Number(process.env.PORT) || 8000;

const FLAG = process.env.FLAG || "flag{this_is_a_sample_flag}";

app.set("view engine", "html");
app.set("views", "views");

app.get("/", (req, res) => {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const filePath = path.join(__dirname, "views", "index.html");

  res.sendFile(filePath);
});

app.post("/submit", (req, res) => {
  const data = req.body;

  const text = data?.text || null;

  if (!text) {
    return res.status(400).json({
      error: "Text field is required.",
    });
  }
  if (text?.length < 200) {
    res.json({
      error: "Text is too short. It must be at least 200 of length.",
    });

    return;
  }

  return res.status(200).json({
    message: "Text received successfully.",
    flag: FLAG,
  });
});

app.use(function (req, res, next) {
  res.status(404).json({
    error: "Not Found",
    message: "The requested resource could not be found.",
  });
});

app.use(function (err, req, res, next) {
  console.error(err.stack);
  res.status(500).json({
    error: "Internal Server Error",
    message: "An unexpected error occurred.",
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
